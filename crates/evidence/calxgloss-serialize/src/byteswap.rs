//! Byte-swap call detection.
//!
//! This module provides [`ByteSwapDetector`], which carries the
//! byte-swap call names a scan reads decompiled bodies against — the
//! POSIX `ntohs`/`ntohl`/`htons`/`htonl` network-order family, the
//! bare `bswap32`, and the GCC `__builtin_bswap16/32/64` builtins —
//! and reads each recognized call site as a byte-order conversion a
//! Rust translation should express through typed big-endian reads.
//!
//! Each name is a [`ByteSwapSignature`]: the callee spelling as the
//! decompiler writes it and the [`width`](ByteSwapSignature::width) of
//! the value it reorders. [`default_byteswaps`] carries the standard
//! name set, and [`ByteSwapDetector::with_default_names`] builds a
//! detector that scans against it.
//!
//! [`ByteSwapDetector::detect`] runs the reading: it walks a decompiled
//! body's direct calls in source order and emits one
//! [`ByteSwapOperation`] per recognized call site — one call is a whole
//! finding, the swap needs no second half to complete the picture.

use crate::types::ByteSwapOperation;
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

// ============================================================
// Byte-swap names
// ============================================================

/// One byte-swap call name the detector recognizes: the callee
/// spelling and the width of the value it reorders.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) reverses the byte order of a value
/// [`width`](Self::width) bits wide — `ntohl` a 32-bit word, `ntohs` a
/// 16-bit one — while where the call sits in the function is the
/// detector's reading. The width decides which sized `byteorder`
/// reader the call site reads as.
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
    /// A signature recognizing the callee spelling `name` as a
    /// byte-swap of a `width`-bit value.
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
/// The detector owns the name set a scan reads bodies against:
/// [`ByteSwapSignature`] records, each a callee spelling and the width
/// it swaps at. The set is configurable — supply it whole through
/// [`with_names`](Self::with_names) or grow it one name at a time with
/// [`add_name`](Self::add_name) — and [`names`](Self::names) reports
/// it in configuration order, so two detectors built the same way scan
/// identically and results diff cleanly. The widths follow the
/// spellings' C prototypes: `ntohs`/`htons` take and return a 16-bit
/// `short`, `ntohl`/`htonl` a 32-bit `unsigned long` on the 32-bit
/// convention the decompiler writes, and the `__builtin_bswapN`
/// spellings name their width in the name itself. The detector holds
/// no Ghidra client of its own and never writes back to the program;
/// one detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteSwapDetector {
    names: Vec<ByteSwapSignature>,
}

impl ByteSwapDetector {
    /// A detector with no names configured: every body it is handed
    /// reads nothing until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name set —
    /// [`default_byteswaps`] — in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_byteswaps())
    }

    /// A detector that scans against exactly `names`, each kept in the
    /// order it is given.
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

    /// The byte-swap call sites one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and reports every
    /// call to a configured name as one [`ByteSwapOperation`]: the
    /// operation is the callee spelling, the width the signature's,
    /// the suggestion the `byteorder` reader for that width, and the
    /// evidence the call's own line. Findings come back in call order,
    /// so two scans of one body diff cleanly.
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

/// Confidence of a byte-swap reading from a single call to a
/// recognized name: the call is explicit and its name is the whole
/// evidence — an `ntohl` is a network-order read wherever it appears —
/// but which endianness the surrounding buffer actually carries is a
/// convention the name implies, not a fact read from the body.
const BYTESWAP_CONFIDENCE: u8 = 70;

/// The Rust pattern a swap at one width reads as: the `byteorder`
/// big-endian reader for that width, the typed stand-in for the
/// host-order-to-network-order hop.
fn suggestion_for(width: u8) -> String {
    format!("byteorder::BE::read_u{width}")
}

/// The control-flow keywords Ghidra writes with a parenthesised
/// operand; none of them is a callee.
const NON_CALL_KEYWORDS: [&str; 7] = ["if", "while", "for", "switch", "case", "return", "sizeof"];

/// A direct call found in a body: the callee name and the byte offset
/// of the callee.
struct CallSite<'a> {
    callee: &'a str,
    offset: usize,
}

/// Every direct call `name(...)` in the body whose callee is a plain
/// identifier, scanned outside string literals so a stray name in a
/// format string cannot be read as a call. A name preceded by an
/// identifier byte is the tail of a longer identifier, and one
/// preceded by a `.` or a `>` is a member access through an object;
/// neither is a plain call — every swap spelling this detector reads
/// is a plain C function name. A call whose `(` never closes — a
/// truncated decompile — yields nothing, and nested calls are each
/// visited.
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                if i > 0
                    && (is_ident_byte(bytes[i - 1]) || bytes[i - 1] == b'.' || bytes[i - 1] == b'>')
                {
                    i += 1;
                    continue;
                }
                let mut j = i;
                while j < bytes.len() && is_ident_byte(bytes[j]) {
                    j += 1;
                }
                let open = skip_ws(bytes, j);
                if bytes.get(open) == Some(&b'(')
                    && !NON_CALL_KEYWORDS.contains(&&body[i..j])
                    && closing_paren(body, open).is_some()
                {
                    calls.push(CallSite {
                        callee: &body[i..j],
                        offset: i,
                    });
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    calls
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

/// The standard byte-swap names: the spellings a scan recognizes as
/// byte-order conversions out of the box — the POSIX network-order
/// family, whose `s` spellings carry a 16-bit `short` and whose `l`
/// spellings a 32-bit word, the bare `bswap32` a program's own
/// hand-rolled swap, and the GCC `__builtin_bswapN` family, which
/// names its width in the spelling.
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
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
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
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
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
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
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
        // One body, every standard spelling: each reads as a swap at
        // the width its signature carries.
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
        // Whole names only: a longer spelling is a different callee,
        // and a member access through an object is no plain call.
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
        // A program with its own hand-rolled swap spelling says so:
        // the custom name reads like a standard one at its width.
        let mut detector = ByteSwapDetector::new();
        detector.add_name(ByteSwapSignature::new("SwapBytes", 32));
        let operations = detector.detect(&function("  uVar1 = SwapBytes(local_18);"));
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].operation, "SwapBytes");
        assert_eq!(operations[0].suggestion, "byteorder::BE::read_u32");
        // The standard spellings the swap replaced read nothing now.
        assert!(
            detector
                .detect(&function("  uVar1 = ntohl(local_18);"))
                .is_empty()
        );
    }
}
