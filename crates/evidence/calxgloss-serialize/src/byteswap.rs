//! Byte-swap call detection.
//!
//! This module provides [`ByteSwapDetector`]. It holds the byte-swap
//! call names the scan checks decompiled bodies against: the POSIX
//! `ntohs`/`ntohl`/`htons`/`htonl` network-order family, the bare
//! `bswap32`, and the GCC `__builtin_bswap16/32/64` builtins. Each
//! call to one of these names is a byte-order conversion that a Rust
//! translation should express through typed big-endian reads.
//!
//! Each name is a [`ByteSwapSignature`]: the callee spelling as the
//! decompiler writes it, and the [`width`](ByteSwapSignature::width)
//! of the value it reorders. [`default_byteswaps`] is the standard name
//! set, and [`ByteSwapDetector::with_default_names`] builds a detector
//! that scans against it.
//!
//! [`ByteSwapDetector::detect`] runs the reading. It walks a decompiled
//! body's direct calls in source order and writes one
//! [`ByteSwapOperation`] for each recognized call site. One call makes
//! a whole finding: a swap needs no second half to complete the
//! picture.

use crate::types::ByteSwapOperation;
use calxgloss_decomp::DecompiledFunction;
use serde::{Deserialize, Serialize};

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at,
};

/// How the call scan is set up: it matches callees written as plain
/// identifiers, skips member accesses, and does not treat C keywords as
/// calls, as in `if (x)`.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Finds every direct call in the body, using the shared pseudo-C scan
/// configured by [`CALL_SCAN`]. This byte-order reading only needs
/// names and lines, so it ignores the arguments the scan reports.
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Byte-swap names
// ============================================================

/// One byte-swap call name the detector recognizes: the callee
/// spelling and the width of the value it reorders.
///
/// A signature is a name, not a shape. It only says that a call to
/// [`name`](Self::name) reverses the byte order of a value
/// [`width`](Self::width) bits wide — `ntohl` a 32-bit word, `ntohs` a
/// 16-bit one. Where the call sits in the function is what the reading
/// works out. The width decides which sized `byteorder` reader the
/// call site reads as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSwapSignature {
    /// The callee spelling as the decompiler writes it, e.g. `ntohl`,
    /// `__builtin_bswap32`.
    pub name: String,
    /// The width, in bits, of the value the call reorders: 16 for the
    /// short spellings, 32 for the word spellings, 64 for the wide
    /// builtin.
    pub width: u8,
}

impl ByteSwapSignature {
    /// Builds a signature that recognizes the callee spelling `name`
    /// as a byte-swap of a `width`-bit value.
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

/// Byte-swap call detection over decompiled functions.
///
/// The detector owns the name set the scan checks bodies against:
/// [`ByteSwapSignature`] records, each one a callee spelling and the
/// width it swaps at. The set is configurable. Supply the whole set
/// through [`with_names`](Self::with_names), or add names one at a time
/// with [`add_name`](Self::add_name). [`names`](Self::names) reports
/// the set in configuration order, so two detectors built the same way
/// scan identically and their results diff cleanly.
///
/// The widths follow the spellings' C prototypes. `ntohs`/`htons` take
/// and return a 16-bit `short`. `ntohl`/`htonl` take and return a
/// 32-bit `unsigned long`, under the 32-bit convention the decompiler
/// writes. The `__builtin_bswapN` spellings state their width in the
/// name itself. The detector holds no scan source of its own and never
/// writes back to the program. One detector serves an entire scan and
/// can be shared by reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteSwapDetector {
    names: Vec<ByteSwapSignature>,
}

impl ByteSwapDetector {
    /// Builds a detector with no names configured. Every body it
    /// receives reads nothing, until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names are
    /// added one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a detector that scans against the standard name set,
    /// [`default_byteswaps`], in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_byteswaps())
    }

    /// Builds a detector that scans against exactly `names`, keeping
    /// each name in the order it is given.
    pub fn with_names(names: impl IntoIterator<Item = ByteSwapSignature>) -> Self {
        Self {
            names: names.into_iter().collect(),
        }
    }

    /// Add one name to the set this detector scans against.
    pub fn add_name(&mut self, name: ByteSwapSignature) {
        self.names.push(name);
    }

    /// The names this detector scans against, in configuration order.
    pub fn names(&self) -> &[ByteSwapSignature] {
        &self.names
    }

    /// Finds the byte-swap call sites in one function's body.
    ///
    /// The reading walks the body's direct calls in source order. It
    /// ignores string literals and only matches whole names. Every call
    /// to a configured name becomes one [`ByteSwapOperation`]: the
    /// operation is the callee spelling, the width comes from the
    /// signature, the suggestion is the `byteorder` reader for that
    /// width, and the evidence is the call's own line. Findings come
    /// back in call order, so two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<ByteSwapOperation> {
        let mut operations = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.names.iter().find(|b| b.name == call.callee) {
                operations.push(ByteSwapOperation {
                    function: func.name.clone(),
                    operation: signature.name.clone(),
                    width: u32::from(signature.width),
                    suggestion: suggestion_for(signature.width),
                    confidence: BYTESWAP_CONFIDENCE.into(),
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

/// The evidence confidence of a byte-swap reading from a single call
/// to a recognized name. The call is explicit, and its name is the
/// whole evidence: an `ntohl` is a network-order read wherever it
/// appears. But the name only implies a convention. It does not show
/// what byte order the surrounding buffer actually uses.
const BYTESWAP_CONFIDENCE: u8 = 70;

/// Builds the Rust pattern that a swap at one width reads as: the
/// `byteorder` big-endian reader for that width. That reader is the
/// typed stand-in for the hop between host order and network order.
fn suggestion_for(width: u8) -> String {
    format!("byteorder::BE::read_u{width}")
}
// ============================================================
// The standard name set
// ============================================================

/// The standard byte-swap names: the spellings the scan recognizes as
/// byte-order conversions without any configuration. First comes the
/// POSIX network-order family, whose `s` spellings mean a 16-bit
/// `short` and whose `l` spellings a 32-bit word. Then the bare
/// `bswap32`, a program's own hand-rolled swap. Last comes the GCC
/// `__builtin_bswapN` family, which states its width in the spelling.
pub fn default_byteswaps() -> Vec<ByteSwapSignature> {
    vec![
        ByteSwapSignature::new("ntohs", 16),
        ByteSwapSignature::new("ntohl", 32),
        ByteSwapSignature::new("htons", 16),
        ByteSwapSignature::new("htonl", 32),
        ByteSwapSignature::new("bswap32", 32),
        ByteSwapSignature::new("__builtin_bswap16", 16),
        ByteSwapSignature::new("__builtin_bswap32", 32),
        ByteSwapSignature::new("__builtin_bswap64", 64),
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
        // Building a detector costs nothing. It starts empty, any two
        // ways of building it are equal, and a clone can take its place.
        let detector = ByteSwapDetector::new();
        assert!(detector.names().is_empty());
        assert_eq!(detector, ByteSwapDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = ByteSwapDetector::with_names([
            ByteSwapSignature::new("ntohl", 32),
            ByteSwapSignature::new("__builtin_bswap64", 64),
        ]);
        // The configuration order is the scan order: two detectors built
        // the same way see the same names in the same order.
        assert_eq!(detector.names().len(), 2);
        assert_eq!(detector.names()[0].name, "ntohl");
        assert_eq!(detector.names()[1].width, 64);
    }

    #[test]
    fn added_names_join_the_set_in_order() {
        let mut detector = ByteSwapDetector::new();
        detector.add_name(ByteSwapSignature::new("ntohl", 32));
        detector.add_name(ByteSwapSignature::new("htonl", 32));
        let names: Vec<&str> = detector.names().iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["ntohl", "htonl"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector runs over a program's functions at the same time,
        // so sharing it by reference across tasks has to stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ByteSwapDetector>();
    }

    #[test]
    fn a_byte_swap_signature_serde_round_trips() {
        let signature = ByteSwapSignature::new("__builtin_bswap64", 64);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"width\":64"));
        let back: ByteSwapSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn the_standard_byteswaps_name_the_network_and_builtin_families() {
        let swaps = default_byteswaps();
        let named: Vec<(&str, u8)> = swaps.iter().map(|b| (b.name.as_str(), b.width)).collect();
        assert_eq!(
            named,
            [
                ("ntohs", 16),
                ("ntohl", 32),
                ("htons", 16),
                ("htonl", 32),
                ("bswap32", 32),
                ("__builtin_bswap16", 16),
                ("__builtin_bswap32", 32),
                ("__builtin_bswap64", 64),
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_set_carries_it() {
        let detector = ByteSwapDetector::with_default_names();
        assert_eq!(detector.names(), default_byteswaps());
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

    fn detect(body: &str) -> Vec<ByteSwapOperation> {
        ByteSwapDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn an_ntohl_is_detected_as_a_32_bit_swap() {
        let operations = detect(
            "\
undefined FUN_18003ab00(void) {
  uVar1 = ntohl(local_18);
  return;
}",
        );
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].function, "FUN_18003ab00");
        assert_eq!(operations[0].operation, "ntohl");
        assert_eq!(operations[0].width, 32);
        assert_eq!(operations[0].suggestion, "byteorder::BE::read_u32");
        assert_eq!(operations[0].confidence, BYTESWAP_CONFIDENCE);
        // The evidence is the call's own line.
        assert_eq!(operations[0].evidence, "uVar1 = ntohl(local_18);");
    }

    #[test]
    fn each_default_spelling_yields_a_finding_naming_its_width() {
        // One body with every standard spelling. Each one reads as a
        // swap at the width its signature gives it.
        let operations = detect(
            "\
  sVar1 = ntohs(uVar2);
  uVar3 = ntohl(uVar4);
  sVar5 = htons(uVar6);
  uVar7 = htonl(uVar8);
  uVar9 = bswap32(uVar10);
  sVar11 = __builtin_bswap16(uVar12);
  uVar13 = __builtin_bswap32(uVar14);
  uVar15 = __builtin_bswap64(uVar16);",
        );
        assert_eq!(operations.len(), 8);
        let widths: Vec<(&str, u32)> = operations
            .iter()
            .map(|o| (o.operation.as_str(), o.width))
            .collect();
        assert_eq!(
            widths,
            [
                ("ntohs", 16),
                ("ntohl", 32),
                ("htons", 16),
                ("htonl", 32),
                ("bswap32", 32),
                ("__builtin_bswap16", 16),
                ("__builtin_bswap32", 32),
                ("__builtin_bswap64", 64),
            ]
        );
        for operation in &operations {
            assert_eq!(
                operation.suggestion,
                format!("byteorder::BE::read_u{}", operation.width)
            );
        }
    }

    #[test]
    fn an_unrelated_body_yields_nothing() {
        assert!(
            detect(
                "\
  uVar1 = uVar2 + 1;
  memcpy(local_10,local_18,4);
  return;"
            )
            .is_empty()
        );
    }

    #[test]
    fn each_call_site_is_its_own_finding_in_call_order() {
        let operations = detect(
            "\
  uVar1 = ntohl(local_18);
  iVar2 = iVar2 + 1;
  uVar3 = ntohl(local_20);",
        );
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].evidence, "uVar1 = ntohl(local_18);");
        assert_eq!(operations[1].evidence, "uVar3 = ntohl(local_20);");
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        assert!(detect("  printf(\"ntohl converts network order\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Only whole names match. A longer spelling is a different callee,
        // and a member access through an object is not a plain call.
        assert!(
            detect(
                "\
  uVar1 = ntohl64(local_18);
  x.ntohl(local_20);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        assert!(detect("  uVar1 = ntohl(local_18;").is_empty());
    }

    #[test]
    fn nested_calls_are_each_visited() {
        let operations = detect("  uVar1 = ntohl(local_18) + ntohl(local_20);");
        assert_eq!(operations.len(), 2);
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = ByteSwapDetector::new();
        let operations = detector.detect(&function("  uVar1 = ntohl(local_18);"));
        assert!(operations.is_empty());
    }

    #[test]
    fn a_custom_name_set_reaches_the_detector() {
        // A program can have its own hand-rolled swap spelling. The
        // custom name reads like a standard one, at the width it is given.
        let mut detector = ByteSwapDetector::new();
        detector.add_name(ByteSwapSignature::new("SwapBytes", 32));
        let operations = detector.detect(&function("  uVar1 = SwapBytes(local_18);"));
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].operation, "SwapBytes");
        assert_eq!(operations[0].suggestion, "byteorder::BE::read_u32");
        // The standard spellings read nothing now, because this detector
        // was never given them.
        assert!(
            detector
                .detect(&function("  uVar1 = ntohl(local_18);"))
                .is_empty()
        );
    }
}
