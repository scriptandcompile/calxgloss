//! Callback registration detection.
//!
//! This module provides [`CallbackRegDetector`], which carries the
//! registration call names a scan reads decompiled bodies against —
//! the `register_callback` and `set_on_message` spellings a program
//! uses to hand a handler to a dispatcher — and reads each recognized
//! call with its callback argument bound.
//!
//! A registration call is the explicit half of callback dispatch:
//! where the fp-array detector reads a table being called, this one
//! reads a handler being *given away* — `register_callback(my_handler)`
//! says a function reference crosses a boundary the Rust translation
//! must keep as a first-class closure.
//!
//! [`CallbackRegDetector::detect`] runs the reading: it walks a
//! decompiled body's direct calls in source order and emits one
//! [`CallbackRegistration`] per recognized call that names its
//! callback — a registration whose callback argument is a literal or
//! an unnamed expression says nothing a prompt could act on, so it
//! passes unrecorded.

use crate::types::CallbackRegistration;
use calxgloss_ghidra::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, closing_paren, line_at,
    skip_string, skip_ws,
};

/// The scan: plain-identifier callees, qualified tails and member
/// accesses skipped, and C keywords are not calls. The registration
/// read re-derives the argument text itself, so the scan's arguments
/// go unused.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>:",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call in the body — the shared pseudo-C scan configured
/// by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Detector
// ============================================================

/// Callback registration detection over decompiled functions.
///
/// The detector owns the registration-name set a scan reads bodies
/// against: plain callee spellings, matched whole. The set is
/// configurable — supply it whole through [`with_names`](Self::with_names)
/// or grow it one name at a time with [`add_name`](Self::add_name) —
/// and [`names`](Self::names) reports it in configuration order, so
/// two detectors built the same way scan identically and results diff
/// cleanly. The standard set ([`default_registration_names`]) names
/// the snake-case and Win32-style spellings decompiled binaries most
/// often use; a program that registers under a different name
/// configures it through [`with_names`](Self::with_names). The
/// detector holds no Ghidra client of its own and never writes back
/// to the program; one detector serves an entire scan and can be
/// shared by reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackRegDetector {
    names: Vec<String>,
}

impl CallbackRegDetector {
    /// A detector with no names configured: every body it is handed
    /// reads nothing until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name set —
    /// [`default_registration_names`] — in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_registration_names())
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

    /// The callback registrations one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and reports every
    /// call to a configured registration name whose callback argument
    /// names a function as one [`CallbackRegistration`]: the
    /// registration is the callee spelling, the callback the argument
    /// with its cast and address-of stripped, the suggestion the
    /// stored closure the boundary reads as, and the evidence the
    /// call's own line. A call whose callback argument is a literal,
    /// a decompiler temporary, or an unnamed expression binds nothing
    /// and passes unrecorded. Findings come back in call order, so
    /// two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<CallbackRegistration> {
        let mut registrations = Vec::new();
        for call in direct_calls(&func.body) {
            if !self.names.iter().any(|n| n == call.callee) {
                continue;
            }
            let Some(open) = argument_open(&func.body, call.offset + call.callee.len()) else {
                continue;
            };
            let Some(close) = closing_paren(&func.body, open) else {
                continue;
            };
            let Some(callback) = bound_callback(&func.body[open + 1..close]) else {
                continue;
            };
            registrations.push(CallbackRegistration {
                function: func.name.clone(),
                registration: call.callee.to_string(),
                callback,
                suggestion: REGISTRATION_SUGGESTION.to_string(),
                confidence: REGISTRATION_CONFIDENCE.into(),
                evidence: line_at(&func.body, call.offset),
            });
        }
        registrations
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a registration reading from a single call to a
/// recognized name with a named callback: the call is explicit and
/// its name plus bound argument are the whole evidence — a handler
/// handed to `register_callback` is a callback wherever it appears —
/// but the closure's exact signature is not read from the body.
const REGISTRATION_CONFIDENCE: u8 = 70;

/// The Rust pattern a callback registration suggests: a boxed closure
/// stored or passed where the original kept a raw function pointer,
/// so the callback boundary survives translation.
const REGISTRATION_SUGGESTION: &str = "Box<dyn Fn(...)>";
/// The offset of the `(` opening `callee`'s argument list, given the
/// offset just past the callee name.
fn argument_open(body: &str, after_callee: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let open = skip_ws(bytes, after_callee);
    (bytes.get(open) == Some(&b'(')).then_some(open)
}

/// The callback a registration call's arguments bind: the first
/// top-level argument that names a function once its cast and
/// leading `&` are stripped.
///
/// Arguments split at top-level commas; each is read as a candidate
/// function reference — `(callback_t)handler` and `&handler` name the
/// same handler the bare spelling does — and the first candidate that
/// is a plain identifier the decompiler did not mint itself wins.
/// Decompiler-minted names (`local_10`, `param_2`, `uVar3`, `this`)
/// name storage, not handlers, so they pass by; a literal, a call
/// expression, or nothing left to bind yields no callback, and the
/// registration passes unrecorded rather than inventing one.
fn bound_callback(args: &str) -> Option<String> {
    top_level_args(args)
        .into_iter()
        .filter_map(strip_to_identifier)
        .find(|name| !is_decompiler_minted(name) && name != "NULL")
}

/// The argument list split at top-level commas — commas inside
/// nested parentheses, brackets, braces, or string literals do not
/// separate arguments.
fn top_level_args(args: &str) -> Vec<&str> {
    let bytes = args.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' if depth == 0 => {
                parts.push(args[start..i].trim());
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let last = args[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// The plain identifier an argument names, once a leading cast
/// `(type)` and a leading `&` are stripped — or `None` when what is
/// left is not a bare identifier.
fn strip_to_identifier(arg: &str) -> Option<String> {
    let mut rest = arg;
    // A cast wraps the argument: `(callback_t)handler`. A cast's own
    // parentheses balance, so the matching `)` marks where the
    // argument itself starts.
    if rest.starts_with('(') {
        let bytes = rest.as_bytes();
        let mut depth = 0usize;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            return None;
        }
        rest = rest[i + 1..].trim();
    }
    // Taking the handler's address names the same handler: `&handler`.
    rest = rest.strip_prefix('&').unwrap_or(rest).trim();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty()
        || name.len() != rest.len()
        || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(name)
}

/// Whether an identifier is one the decompiler minted for storage —
/// a local, a parameter, a variable, or the receiver — rather than a
/// name the program itself gave a handler.
fn is_decompiler_minted(name: &str) -> bool {
    const MINTED_PREFIXES: [&str; 7] = ["local_", "param_", "uVar", "iVar", "sVar", "cVar", "fVar"];
    name == "this" || MINTED_PREFIXES.iter().any(|p| name.starts_with(p))
}
// ============================================================
// The standard name set
// ============================================================

/// The standard registration names: the spellings a scan recognizes
/// as callback registrations out of the box — the snake-case
/// `register_*` and `set_*` spellings a C codebase writes by hand and
/// the PascalCase `Set*` spellings a Win32-flavored codebase exports.
/// These are conventions, not laws: a program that registers under a
/// different name configures it through [`CallbackRegDetector::with_names`].
pub fn default_registration_names() -> Vec<String> {
    [
        "register_callback",
        "register_handler",
        "set_callback",
        "set_handler",
        "set_on_message",
        "SetCallback",
        "SetHandler",
        "SetOnMessage",
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
        let detector = CallbackRegDetector::new();
        assert!(detector.names().is_empty());
        assert_eq!(detector, CallbackRegDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = CallbackRegDetector::with_names(["register_callback", "set_handler"]);
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        let names: Vec<&str> = detector.names().iter().map(String::as_str).collect();
        assert_eq!(names, ["register_callback", "set_handler"]);
    }

    #[test]
    fn added_names_join_the_set_in_order() {
        let mut detector = CallbackRegDetector::new();
        detector.add_name("register_callback");
        detector.add_name("SetOnMessage");
        let names: Vec<&str> = detector.names().iter().map(String::as_str).collect();
        assert_eq!(names, ["register_callback", "SetOnMessage"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CallbackRegDetector>();
    }

    #[test]
    fn the_standard_names_cover_the_snake_and_pascal_case_families() {
        let names = default_registration_names();
        let named: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(
            named,
            [
                "register_callback",
                "register_handler",
                "set_callback",
                "set_handler",
                "set_on_message",
                "SetCallback",
                "SetHandler",
                "SetOnMessage",
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_set_carries_it() {
        let detector = CallbackRegDetector::with_default_names();
        assert_eq!(detector.names(), default_registration_names());
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

    fn detect(body: &str) -> Vec<CallbackRegistration> {
        CallbackRegDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn a_registration_with_a_named_callback_is_detected() {
        let registrations = detect("  register_callback(my_handler);");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].function, "FUN_18003ab00");
        assert_eq!(registrations[0].registration, "register_callback");
        assert_eq!(registrations[0].callback, "my_handler");
        assert_eq!(registrations[0].suggestion, "Box<dyn Fn(...)>");
        assert_eq!(registrations[0].confidence, REGISTRATION_CONFIDENCE);
        // The evidence is the call's own line.
        assert_eq!(registrations[0].evidence, "register_callback(my_handler);");
    }

    #[test]
    fn an_address_of_argument_binds_the_same_handler() {
        let registrations = detect("  set_callback(&msg_handler);");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].registration, "set_callback");
        assert_eq!(registrations[0].callback, "msg_handler");
    }

    #[test]
    fn a_cast_argument_binds_the_same_handler() {
        let registrations = detect("  register_handler((callback_t *)on_message);");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].callback, "on_message");
    }

    #[test]
    fn a_leading_object_argument_does_not_steal_the_binding() {
        // `set_on_message(this, handler)` hands the receiver first;
        // the handler is the argument that names a function.
        let registrations = detect("  set_on_message(this,msg_handler);");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].callback, "msg_handler");
    }

    #[test]
    fn the_pascal_case_spellings_are_recognized_too() {
        let registrations = detect("  SetOnMessage(FUN_1800412a0);");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].registration, "SetOnMessage");
        assert_eq!(registrations[0].callback, "FUN_1800412a0");
    }

    #[test]
    fn each_registration_site_is_its_own_finding_in_call_order() {
        let registrations = detect(
            "\
  register_callback(handler_a);
  iVar1 = iVar1 + 1;
  set_handler(handler_b);",
        );
        assert_eq!(registrations.len(), 2);
        assert_eq!(registrations[0].evidence, "register_callback(handler_a);");
        assert_eq!(registrations[1].evidence, "set_handler(handler_b);");
    }

    #[test]
    fn a_registration_that_binds_nothing_records_nothing() {
        // A literal, a decompiler temporary, or a call expression
        // names no handler a prompt could act on.
        assert!(
            detect(
                "\
  register_callback((callback_t *)0x0);
  set_callback(local_10);
  register_handler(get_default());
  set_on_message(NULL);",
            )
            .is_empty()
        );
    }

    #[test]
    fn nested_calls_do_not_disturb_detection() {
        // A nested call in the argument list, and a registration
        // nested inside another call, both still bind the handler.
        let records = detect(
            "\
  register_callback(my_handler, setup(1, 2));
  atexit(register_handler(thunk));",
        );
        assert_eq!(
            records.len(),
            2,
            "both registrations read through the nesting"
        );
        assert_eq!(records[0].callback, "my_handler");
        assert_eq!(records[1].callback, "thunk");
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        assert!(detect("  printf(\"register_callback my_handler\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different callee,
        // and a member access through an object is no plain call.
        assert!(
            detect(
                "\
  my_register_callback(my_handler);
  obj.set_callback(my_handler);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        assert!(detect("  register_callback(my_handler;").is_empty());
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = CallbackRegDetector::new();
        let registrations = detector.detect(&function("  register_callback(my_handler);"));
        assert!(registrations.is_empty());
    }

    #[test]
    fn custom_names_behave_like_the_standard_ones() {
        // The name set is swappable whole: a program that registers
        // under its own spelling scans the same way.
        let detector = CallbackRegDetector::with_names(["HookMessage"]);
        let registrations = detector.detect(&function("  HookMessage(wnd_proc);"));
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].registration, "HookMessage");
        assert_eq!(registrations[0].callback, "wnd_proc");
        assert_eq!(registrations[0].confidence, REGISTRATION_CONFIDENCE);
    }
}
