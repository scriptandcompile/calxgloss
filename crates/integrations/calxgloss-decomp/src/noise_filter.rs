//! The decompiler-noise pre-filter: compiler theater stripped from the
//! pseudo-C every consumer sees (issue #232, first family issue #271).
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

/// The family label the debug log names. Labels are stable across releases
/// so an operator's log filter keeps working as families join.
const NAMED_GUARD_CALLS: &str = "named-guard-calls";

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
/// Recognizers compose: each sees the body as the previous family left it,
/// so a future epilogue recognizer can strip an `if` wrapper a named-guard
/// call already hollowed once the conservative gate for that shape exists.
fn filter_body(body: &str) -> (String, Vec<&'static str>) {
    let mut stripped = body.to_string();
    let mut families: Vec<&'static str> = Vec::new();
    if let Some(after_calls) = strip_named_guard_calls(&stripped) {
        stripped = after_calls;
        families.push(NAMED_GUARD_CALLS);
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
/// Answers [`None`] when no line matched — and also when every line with
/// real content matched: a body left with not one word in it is a function
/// that *is* the guard code, and the never-empties rule passes it through
/// whole.
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
    (removed && stripped.chars().any(|c| c.is_alphanumeric())).then_some(stripped)
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
    }
}
