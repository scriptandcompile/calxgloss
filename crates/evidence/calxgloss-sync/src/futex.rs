//! Futex-based synchronization detection.
//!
//! This module provides [`FutexDetector`], which recognizes direct
//! `futex` calls and `syscall(SYS_futex, …)` shapes in a decompiled
//! body and reads each call site as raw futex synchronization. The
//! suggested shape is standard synchronization — `std::sync::Mutex`/
//! `Condvar` — rather than transliterated syscalls.
//!
//! [`FutexDetector::with_default_names`] builds a detector that scans
//! against the standard spellings, and [`FutexDetector::with_names`]
//! builds one against caller-supplied names, so custom spellings
//! reach the scan through the same engine builder the other detectors
//! enjoy.

use crate::types::Futex;
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    skip_char, skip_string,
};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords — `if (x)` — not calls.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

/// The futex spelling for the suggested Rust synchronization.
const SUGGESTION: &str = "std::sync::Mutex/Condvar";

/// Confidence of a futex reading from a single call site: the call is
/// explicit and its spelling is the whole evidence.
const FUTEX_CONFIDENCE: u8 = 70;

// ============================================================
// Detector
// ============================================================

/// Futex-based synchronization detection over decompiled functions.
///
/// The detector owns the set of direct call spellings a scan reads
/// bodies against — `futex` out of the box — alongside the
/// `syscall(SYS_futex, …)` shape, which it recognizes whenever the
/// detector carries any configured name. Both are configurable through
/// [`with_names`](Self::with_names) or [`add_name`](Self::add_name), and
/// [`names`](Self::names) reports them in configuration order, so two
/// detectors built the same way scan identically and results diff
/// cleanly. The detector holds no scan source of its own and never
/// writes back to the program; one detector serves an entire scan and
/// can be shared by reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FutexDetector {
    names: Vec<String>,
}

impl FutexDetector {
    /// A detector with no names configured: every body it is handed
    /// reports nothing until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name set —
    /// [`default_futexes`] — in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_futexes())
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

    /// Convenience alias mirroring the async detector's per-family
    /// name accessors.
    pub fn futex_names(&self) -> &[String] {
        &self.names
    }

    pub fn futexes(&self) -> &[String] {
        &self.names
    }

    pub fn calls(&self) -> &[String] {
        &self.names
    }

    /// The futex call sites one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and reports each
    /// direct call to a configured name, and each `syscall(SYS_futex,
    /// …)` shape, as one [`Futex`]. When the call spells
    /// `FUTEX_WAIT` or `FUTEX_WAKE` anywhere in its argument list,
    /// that name is the operation; otherwise the operation is the
    /// call's own spelling. Findings come back in call order, so two
    /// scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<Futex> {
        if self.names.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for call in direct_calls(&func.body) {
            let direct = self.names.iter().any(|name| name == call.callee);
            let syscall_futex = call.callee == "syscall"
                && call
                    .args
                    .first()
                    .map(|arg| arg.trim() == "SYS_futex")
                    .unwrap_or(false);
            if direct || syscall_futex {
                let operation = futex_operation(&func.body, call.offset, call.close)
                    .unwrap_or_else(|| call.callee.to_string());
                out.push(Futex {
                    function: func.name.clone(),
                    operation,
                    suggestion: SUGGESTION.to_string(),
                    confidence: FUTEX_CONFIDENCE.into(),
                    evidence: line_at(&func.body, call.offset),
                });
            }
        }
        out
    }
}

// ============================================================
// The reading
// ============================================================

/// Search one call site's span for a `FUTEX_WAIT` or `FUTEX_WAKE`
/// token spelled outside string and char literals. Anything else —
/// names inside strings, longer identifiers that merely contain one
/// of the two words — yields nothing.
fn futex_operation(body: &str, start: usize, end: usize) -> Option<String> {
    let bytes = body.as_bytes();
    let end = end.min(bytes.len().saturating_sub(1));
    let mut i = start;
    while i <= end {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => {
                let mut j = i;
                while j < bytes.len() && is_ident_byte(bytes[j]) {
                    j += 1;
                }
                let word = &body[i..j];
                if (word == "FUTEX_WAIT" || word == "FUTEX_WAKE")
                    && (i == 0 || !is_ident_byte(bytes[i - 1]))
                    && (j >= bytes.len() || !is_ident_byte(bytes[j]))
                {
                    return Some(word.to_string());
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    None
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard direct futex call names: the spellings a scan recognizes
/// as futex synchronization out of the box.
pub fn default_futexes() -> Vec<String> {
    vec!["futex".into()]
}

pub fn default_futex() -> Vec<String> {
    default_futexes()
}

pub fn default_futex_names() -> Vec<String> {
    default_futexes()
}

pub fn default_futex_calls() -> Vec<String> {
    default_futexes()
}

pub fn default_syscall_names() -> Vec<String> {
    vec!["syscall".into()]
}

pub fn default_sys_futex_names() -> Vec<String> {
    vec!["SYS_futex".into()]
}

// ============================================================
// Tests (compile-time basic)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_decomp::DecompiledFunction;

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    #[test]
    fn disabled_when_empty() {
        let d = FutexDetector::new();
        assert!(d.detect(&function("futex(&u, FUTEX_WAIT, 0);")).is_empty());
        assert!(
            d.detect(&function("syscall(SYS_futex, &u, FUTEX_WAKE, 0);"))
                .is_empty()
        );
    }

    #[test]
    fn direct_and_syscall_detected() {
        let d = FutexDetector::with_default_names();
        let findings = d.detect(&function(
            "  futex(&u, FUTEX_WAIT, 0);\n  syscall(SYS_futex, &u, FUTEX_WAKE, 0);",
        ));
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].operation, "FUTEX_WAIT");
        assert_eq!(findings[1].operation, "FUTEX_WAKE");
    }
}
