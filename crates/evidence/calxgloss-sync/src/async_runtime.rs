//! Async runtime detection.
//!
//! [`AsyncDetector`] holds the event-loop call names the scan reads
//! decompiled bodies against. The names are split into two sets: the
//! shapes that read as `tokio` (the I/O completion port and epoll
//! families) and the shapes that read as an explicit event loop (the
//! Win32 message pump). The detector reads each recognized call site
//! as an async-runtime record.
//!
//! [`AsyncDetector::with_default_names`] builds a detector that scans
//! against the standard sets, and [`AsyncDetector::with_names`] builds
//! one against sets the caller supplies. Custom spellings reach the
//! scan through the same `SyncEngine` builder methods the other
//! detectors have.

use crate::types::AsyncRuntime;
use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at,
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

/// Event-loop shapes that read as the `tokio` runtime family.
const TOKIO_NAMES: &[&str] = &[
    "CreateIoCompletionPort",
    "GetQueuedCompletionStatus",
    "epoll_create",
    "epoll_create1",
    "epoll_wait",
    "select",
    "poll",
];

/// Event-loop shapes that read as an explicit event loop (the Win32
/// message pump).
const EVENT_LOOP_NAMES: &[&str] = &[
    "GetMessage",
    "GetMessageA",
    "GetMessageW",
    "DispatchMessage",
    "DispatchMessageA",
    "DispatchMessageW",
];

/// The suggested Rust shape for a completion-port or epoll family.
const TOKIO_SUGGESTION: &str = "tokio";
/// The suggested Rust shape for the message-pump family.
const EVENT_LOOP_SUGGESTION: &str = "an explicit event loop";

/// Evidence confidence of an async-runtime reading from a single call
/// to a recognized name: the call is explicit and its name is the
/// whole evidence.
const ASYNC_CONFIDENCE: u8 = 70;

// ============================================================
// Detector
// ============================================================

/// Async runtime detection over decompiled functions.
///
/// The detector owns the two name sets the scan reads bodies against:
/// the event-loop spellings that read as `tokio`, and the spellings
/// that read as an explicit event loop. Both sets are configurable —
/// supply them whole through [`with_names`](Self::with_names) or grow
/// them one name at a time. The accessors report the names in
/// configuration order, so two detectors built the same way scan
/// identically and their results diff cleanly. The detector holds no
/// scan source of its own and never writes back to the program. One
/// detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsyncDetector {
    tokio_names: Vec<String>,
    event_loop_names: Vec<String>,
}

impl AsyncDetector {
    /// A detector with no names configured: every body it is handed
    /// reports nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time.
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets.
    pub fn with_default_names() -> Self {
        Self::with_names(
            TOKIO_NAMES.iter().copied(),
            EVENT_LOOP_NAMES.iter().copied(),
        )
    }

    /// A detector that scans against exactly `tokio_names` and
    /// `event_loop_names`, each kept in the order it is given.
    pub fn with_names(
        tokio_names: impl IntoIterator<Item = impl Into<String>>,
        event_loop_names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            tokio_names: tokio_names.into_iter().map(Into::into).collect(),
            event_loop_names: event_loop_names.into_iter().map(Into::into).collect(),
        }
    }

    pub fn add_tokio_name(&mut self, name: impl Into<String>) {
        self.tokio_names.push(name.into());
    }

    pub fn add_event_loop_name(&mut self, name: impl Into<String>) {
        self.event_loop_names.push(name.into());
    }

    pub fn add_name(&mut self, name: impl Into<String>) {
        self.tokio_names.push(name.into());
    }

    pub fn add_tokio(&mut self, name: impl Into<String>) {
        self.tokio_names.push(name.into());
    }

    pub fn add_event_loop(&mut self, name: impl Into<String>) {
        self.event_loop_names.push(name.into());
    }

    pub fn tokio_names(&self) -> &[String] {
        &self.tokio_names
    }

    pub fn event_loop_names(&self) -> &[String] {
        &self.event_loop_names
    }

    pub fn tokio(&self) -> &[String] {
        &self.tokio_names
    }

    pub fn event_loops(&self) -> &[String] {
        &self.event_loop_names
    }

    pub fn event_loop(&self) -> &[String] {
        &self.event_loop_names
    }

    /// Every configured name in one list, kept for compatibility with
    /// the other detectors' accessor name.
    pub fn names(&self) -> Vec<String> {
        let mut out = self.tokio_names.clone();
        out.extend(self.event_loop_names.clone());
        out
    }

    pub fn detect(&self, func: &DecompiledFunction) -> Vec<AsyncRuntime> {
        let mut out = Vec::new();
        for call in direct_calls(&func.body) {
            if self.tokio_names.iter().any(|n| n == call.callee) {
                out.push(AsyncRuntime {
                    function: func.name.clone(),
                    operation: call.callee.to_string(),
                    suggestion: TOKIO_SUGGESTION.to_string(),
                    confidence: ASYNC_CONFIDENCE.into(),
                    evidence: line_at(&func.body, call.offset),
                });
            } else if self.event_loop_names.iter().any(|n| n == call.callee) {
                out.push(AsyncRuntime {
                    function: func.name.clone(),
                    operation: call.callee.to_string(),
                    suggestion: EVENT_LOOP_SUGGESTION.to_string(),
                    confidence: ASYNC_CONFIDENCE.into(),
                    evidence: line_at(&func.body, call.offset),
                });
            }
        }
        out
    }
}

// ============================================================
// The standard name sets
// ============================================================

pub fn default_tokio_names() -> Vec<String> {
    TOKIO_NAMES.iter().map(|s| (*s).to_string()).collect()
}

pub fn default_event_loop_names() -> Vec<String> {
    EVENT_LOOP_NAMES.iter().map(|s| (*s).to_string()).collect()
}

pub fn default_async_runtime_names() -> Vec<String> {
    let mut out = default_tokio_names();
    out.extend(default_event_loop_names());
    out
}

// ============================================================
// Tests
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
    fn a_new_detector_starts_with_no_names() {
        let detector = AsyncDetector::new();
        assert!(detector.tokio_names().is_empty());
        assert!(detector.event_loop_names().is_empty());
        assert_eq!(detector, AsyncDetector::default());
    }

    #[test]
    fn standard_names_are_carried() {
        let detector = AsyncDetector::with_default_names();
        assert!(
            detector
                .tokio_names()
                .contains(&"GetQueuedCompletionStatus".to_string())
        );
        assert!(
            detector
                .event_loop_names()
                .contains(&"DispatchMessage".to_string())
        );
    }

    #[test]
    fn each_call_site_is_its_own_finding_in_call_order() {
        let d = AsyncDetector::with_default_names();
        let ops = d.detect(&function(
            "  GetQueuedCompletionStatus(h,0,0,0,0);\n  DispatchMessage(&msg);",
        ));
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].suggestion, "tokio");
        assert_eq!(ops[1].suggestion, "an explicit event loop");
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        let d = AsyncDetector::with_default_names();
        assert!(
            d.detect(&function("  printf(\"GetQueuedCompletionStatus\");"))
                .is_empty()
        );
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        let d = AsyncDetector::with_default_names();
        assert!(
            d.detect(&function("  x.GetQueuedCompletionStatus(h);"))
                .is_empty()
        );
        assert!(
            d.detect(&function("  GetQueuedCompletionStatusEx(h);"))
                .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        let d = AsyncDetector::with_default_names();
        assert!(
            d.detect(&function("  GetQueuedCompletionStatus(h;"))
                .is_empty()
        );
    }
}
