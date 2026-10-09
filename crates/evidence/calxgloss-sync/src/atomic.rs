//! Atomic operation detection.
//!
//! This module provides [`AtomicDetector`], which carries the atomic
//! call names a scan reads decompiled bodies against — the Win32
//! `InterlockedIncrement`/`InterlockedDecrement` pair and the GCC
//! `__atomic_fetch_add`/`__sync_fetch_and_add` builtins — and reads
//! each recognized call site as an operation on a Rust atomic type.
//!
//! Each name is an [`AtomicSignature`]: the callee spelling as the
//! decompiler writes it and the [`width`](AtomicSignature::width) of
//! the value it operates on. [`default_atomics`] carries the standard
//! name set, and [`AtomicDetector::with_default_names`] builds a
//! detector that scans against it.
//!
//! [`AtomicDetector::detect`] runs the reading: it walks a decompiled
//! body's direct calls in source order and emits one
//! [`AtomicOperation`] per recognized call site — an atomic needs no
//! release to complete the picture, so unlike the lock pairing one
//! call is a whole finding.

use crate::types::AtomicOperation;
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

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

/// Every direct call in the body — the shared pseudo-C scan configured
/// by [`CALL_SCAN`]. The atomics read only names and lines, so the
/// scan's arguments go unused.
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Atomic names
// ============================================================

/// One atomic call name the detector recognizes: the callee spelling
/// and the width of the value it operates on.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) performs a read-modify-write on a value
/// [`width`](Self::width) bits wide — `InterlockedIncrement` a 32-bit
/// counter, `__atomic_fetch_add` a 64-bit one — while where the call
/// sits in the function is the detector's reading. The width decides
/// which sized Rust atomic type the call site reads as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `InterlockedIncrement`, `__atomic_fetch_add`.
    pub name: String,
    /// The width, in bits, of the value the operation reads and
    /// writes: 32 for the Win32 interlocked family, 64 for the GCC
    /// builtins by default.
    pub width: u8,
}

impl AtomicSignature {
    /// A signature recognizing the callee spelling `name` as an
    /// atomic operation on a `width`-bit value.
    pub fn new(name: impl Into<String>, width: u8) -> Self {
        Self {
            name: name.into(),
            width,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Atomic operation detection over decompiled functions.
///
/// The detector owns the name set a scan reads bodies against:
/// [`AtomicSignature`] records, each a callee spelling and the width
/// it operates at. The set is configurable — supply it whole through
/// [`with_names`](Self::with_names) or grow it one name at a time with
/// [`add_name`](Self::add_name) — and [`names`](Self::names) reports
/// it in configuration order, so two detectors built the same way scan
/// identically and results diff cleanly. The widths are a documented
/// default, not a law: the Win32 interlocked calls really do carry a
/// `LONG`, but the GCC builtins are width-polymorphic, and the 64-bit
/// default for them is a convention a per-scan override through
/// [`with_names`](Self::with_names) can restate for a program whose
/// counters are known to be narrower. The detector holds no Ghidra
/// client of its own and never writes back to the program; one
/// detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtomicDetector {
    names: Vec<AtomicSignature>,
}

impl AtomicDetector {
    /// A detector with no names configured: every body it is handed
    /// reads nothing until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name set —
    /// [`default_atomics`] — in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_atomics())
    }

    /// A detector that scans against exactly `names`, each kept in the
    /// order it is given.
    pub fn with_names(names: impl IntoIterator<Item = AtomicSignature>) -> Self {
        Self {
            names: names.into_iter().collect(),
        }
    }

    /// Add one name to the set this detector scans against.
    pub fn add_name(&mut self, name: AtomicSignature) {
        self.names.push(name);
    }

    /// The names this detector scans against, in configuration order.
    pub fn names(&self) -> &[AtomicSignature] {
        &self.names
    }

    /// The atomic call sites one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and reports every
    /// call to a configured name as one [`AtomicOperation`]: the
    /// operation is the callee spelling, the suggestion the sized
    /// Rust atomic type the signature's width names, and the evidence
    /// the call's own line. Findings come back in call order, so two
    /// scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<AtomicOperation> {
        let mut operations = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.names.iter().find(|a| a.name == call.callee) {
                operations.push(AtomicOperation {
                    function: func.name.clone(),
                    operation: signature.name.clone(),
                    suggestion: suggestion_for(signature.width),
                    confidence: ATOMIC_CONFIDENCE.into(),
                    evidence: line_at(&func.body, call.offset),
                });
            }
        }
        operations
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of an atomic reading from a single call to a recognized
/// name: the call is explicit and its name is the whole evidence —
/// an interlocked increment is an atomic increment wherever it
/// appears — but the width of the value behind the pointer is the
/// signature's default, not a fact read from the body.
const ATOMIC_CONFIDENCE: u8 = 70;

/// The Rust atomic type an operation at one width reads as.
fn suggestion_for(width: u8) -> String {
    format!("std::sync::atomic::AtomicU{width}")
}
// ============================================================
// The standard name set
// ============================================================

/// The standard atomic names: the spellings a scan recognizes as
/// atomic operations out of the box — the Win32 interlocked
/// increment and decrement, which carry a 32-bit `LONG`, and the GCC
/// `__atomic` and `__sync` fetch-and-add builtins, defaulted to 64
/// bits. The builtins are width-polymorphic in C; the 64-bit default
/// is the convention the suggestion is written against, and a
/// per-scan override through [`AtomicDetector::with_names`] can
/// restate it.
pub fn default_atomics() -> Vec<AtomicSignature> {
    vec![
        AtomicSignature::new("InterlockedIncrement", 32),
        AtomicSignature::new("InterlockedDecrement", 32),
        AtomicSignature::new("__atomic_fetch_add", 64),
        AtomicSignature::new("__sync_fetch_and_add", 64),
    ]
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
        let detector = AtomicDetector::new();
        assert!(detector.names().is_empty());
        assert_eq!(detector, AtomicDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = AtomicDetector::with_names([
            AtomicSignature::new("InterlockedIncrement", 32),
            AtomicSignature::new("__atomic_fetch_add", 64),
        ]);
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.names().len(), 2);
        assert_eq!(detector.names()[0].name, "InterlockedIncrement");
        assert_eq!(detector.names()[1].width, 64);
    }

    #[test]
    fn added_names_join_the_set_in_order() {
        let mut detector = AtomicDetector::new();
        detector.add_name(AtomicSignature::new("InterlockedIncrement", 32));
        detector.add_name(AtomicSignature::new("InterlockedDecrement", 32));
        let names: Vec<&str> = detector.names().iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["InterlockedIncrement", "InterlockedDecrement"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AtomicDetector>();
    }

    #[test]
    fn an_atomic_signature_serde_round_trips() {
        let signature = AtomicSignature::new("__atomic_fetch_add", 64);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"width\":64"));
        let back: AtomicSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn the_standard_atomics_name_the_interlocked_and_builtin_families() {
        let atomics = default_atomics();
        let named: Vec<(&str, u8)> = atomics.iter().map(|a| (a.name.as_str(), a.width)).collect();
        assert_eq!(
            named,
            [
                ("InterlockedIncrement", 32),
                ("InterlockedDecrement", 32),
                ("__atomic_fetch_add", 64),
                ("__sync_fetch_and_add", 64),
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_set_carries_it() {
        let detector = AtomicDetector::with_default_names();
        assert_eq!(detector.names(), default_atomics());
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

    fn detect(body: &str) -> Vec<AtomicOperation> {
        AtomicDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn an_interlocked_increment_is_detected_as_a_32_bit_atomic() {
        let operations = detect(
            "\
undefined FUN_18003ab00(void) {
  uVar1 = InterlockedIncrement(&local_18);
  return;
}",
        );
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].function, "FUN_18003ab00");
        assert_eq!(operations[0].operation, "InterlockedIncrement");
        assert_eq!(operations[0].suggestion, "std::sync::atomic::AtomicU32");
        assert_eq!(operations[0].confidence, ATOMIC_CONFIDENCE);
        // The evidence is the call's own line.
        assert_eq!(
            operations[0].evidence,
            "uVar1 = InterlockedIncrement(&local_18);"
        );
    }

    #[test]
    fn an_interlocked_decrement_is_detected_too() {
        let operations = detect("  uVar1 = InterlockedDecrement(&local_18);");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].operation, "InterlockedDecrement");
        assert_eq!(operations[0].suggestion, "std::sync::atomic::AtomicU32");
    }

    #[test]
    fn the_gcc_builtins_read_as_64_bit_atomics_by_default() {
        // The builtins are width-polymorphic in C; the 64-bit default
        // is the documented convention behind this suggestion.
        let operations = detect(
            "\
  __atomic_fetch_add(&counter,1,5);
  __sync_fetch_and_add(&counter,1);",
        );
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].operation, "__atomic_fetch_add");
        assert_eq!(operations[0].suggestion, "std::sync::atomic::AtomicU64");
        assert_eq!(operations[1].operation, "__sync_fetch_and_add");
        assert_eq!(operations[1].suggestion, "std::sync::atomic::AtomicU64");
    }

    #[test]
    fn each_call_site_is_its_own_finding_in_call_order() {
        let operations = detect(
            "\
  uVar1 = InterlockedIncrement(&local_18);
  iVar2 = iVar2 + 1;
  uVar3 = InterlockedIncrement(&local_20);",
        );
        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations[0].evidence,
            "uVar1 = InterlockedIncrement(&local_18);"
        );
        assert_eq!(
            operations[1].evidence,
            "uVar3 = InterlockedIncrement(&local_20);"
        );
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        assert!(detect("  printf(\"InterlockedIncrement counter\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different callee,
        // and a member access through an object is no plain call.
        assert!(
            detect(
                "\
  uVar1 = InterlockedIncrementEx(&local_18,1);
  x.InterlockedIncrement(&local_20);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        assert!(detect("  uVar1 = InterlockedIncrement(&local_18;").is_empty());
    }

    #[test]
    fn nested_calls_are_each_visited() {
        let operations =
            detect("  uVar1 = InterlockedIncrement(&local_18) + InterlockedIncrement(&local_20);");
        assert_eq!(operations.len(), 2);
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = AtomicDetector::new();
        let operations = detector.detect(&function("  uVar1 = InterlockedIncrement(&local_18);"));
        assert!(operations.is_empty());
    }

    #[test]
    fn custom_names_and_widths_read_like_the_standard_ones() {
        // The width default is swappable: a scan that knows this
        // program's builtin counters are 32-bit says so.
        let mut detector = AtomicDetector::new();
        detector.add_name(AtomicSignature::new("__atomic_fetch_add", 32));
        let operations = detector.detect(&function("  __atomic_fetch_add(&counter,1,5);"));
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].suggestion, "std::sync::atomic::AtomicU32");
    }
}
