//! Calling-convention detection off the machine listing: the Microsoft
//! x64 shape channels.
//!
//! Where [`crate::stack_discipline`] reads the 32-bit stack discipline
//! an `esp`-spelled listing spells, this detector reads the 64-bit call
//! shape an `rsp`-spelled one spells. A function whose listing shows
//!
//! - **shadow-space allocation in its prologue** — Microsoft x64
//!   reserves a 32-byte home region for the four register arguments, so
//!   a `sub rsp, N` before the first call with `N` at least
//!   [`SHADOW_SPACE_BYTES`] states the frame the convention demands;
//! - **register-first arguments** — the listing spells one of the four
//!   argument registers ([`ARGUMENT_REGISTERS`]), which is what the home
//!   region exists to home;
//! - **no callee or caller stack cleanup** — no `ret N` anywhere, and no
//!   `add rsp, N` right after a call whose count fails to free the
//!   prologue's own allocation: the convention leaves the stack to the
//!   frame, so any real cleanup contradicts the reading;
//!
//! reads [`CallingConvention::MicrosoftX64`] at the shape-only band
//! ([`X64_SHAPE_CONFIDENCE`]), keyed by the function whose listing it is
//! and evidenced by the prologue line that allocates the shadow space.
//! The reading is what stops the translator from inventing stack-cleanup
//! logic for a 64-bit function.
//!
//! A shape is never a spelling: no feature names the convention
//! outright, so the reading sits below every exact channel and nothing
//! self-upgrades — the cross-function corroboration pass (issue #249)
//! is what raises it above this tier. Any feature missing, and any
//! contradicted feature, yields no reading rather than a guess about
//! which convention the function carries.
//!
//! The family keys on the stack register spelled in the listing itself,
//! riding the same machine-class dispatch as the 32-bit family: the
//! [`crate::stack_discipline`] entry point routes an `rsp`-spelled
//! listing here and an `esp`-spelled one to the x86 channels, so the two
//! families never cross-fire — a 32-bit rule never reads a 64-bit
//! function and this family never reads a 32-bit one.

use crate::convention::convention_record;
use crate::stack_discipline::{
    declared_count, instruction, operands, spells_register, split_instruction,
};
use crate::types::{CallingConvention, InferenceMethod, InferredType};

/// Confidence of the shape-only band: the three features corroborate one
/// another within one body, but a shape is never a spelling — none of
/// them names the convention outright — so this is the most modest of
/// the listing-borne readings, sitting below the caller-cleanup band
/// (70) and every exact channel. Nothing self-upgrades; the
/// cross-function corroboration pass (issue #249) is what raises a
/// reading above this tier.
const X64_SHAPE_CONFIDENCE: u8 = 65;

/// The shadow space Microsoft x64 reserves for the four register
/// arguments: 32 bytes of home space, so a prologue subtracting at
/// least this from `rsp` is allocating the region the convention
/// demands. A real frame often rounds up — `0x28` with the mandatory
/// 16-byte alignment is the commonest spelling — which is why the test
/// is at-least, not equal.
const SHADOW_SPACE_BYTES: u64 = 0x20;

/// The registers Microsoft x64 calls its first four integer arguments
/// in. A listing that spells none of them shows no register argument
/// being homed or used, and the home region alone — a `sub rsp, 0x28`
/// on a void function with a large frame — is not enough to read the
/// convention.
const ARGUMENT_REGISTERS: &[&str] = &["rcx", "rdx", "r8", "r9"];

/// The prologue's shadow-space allocation: the first `sub rsp, N`
/// before the first call subtracting at least the home region — the
/// frame Microsoft x64 demands. A `sub rsp` after the first call is
/// mid-body frame bookkeeping, not a prologue. Returns the row itself,
/// which is the reading's evidence, with the byte count it subtracts.
/// Shared with the cross-function corroboration pass of
/// [`crate::corroboration`], which needs the same count to tell a
/// caller's frame teardown from a caller-side cleanup at a call site.
pub(crate) fn shadow_space<'a>(rows: &[&'a str]) -> Option<(&'a str, u64)> {
    let prologue_end = rows
        .iter()
        .position(|row| {
            split_instruction(instruction(row))
                .0
                .eq_ignore_ascii_case("call")
        })
        .unwrap_or(rows.len());
    rows[..prologue_end].iter().find_map(|row| {
        let (mnemonic, operand_text) = split_instruction(instruction(row));
        if !mnemonic.eq_ignore_ascii_case("sub") {
            return None;
        }
        let parts = operands(operand_text);
        if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("rsp") {
            return None;
        }
        declared_count(parts[1])
            .filter(|count| *count >= SHADOW_SPACE_BYTES)
            .map(|count| (*row, count))
    })
}

/// Whether the listing spells a cleanup the convention never leaves
/// behind: a `ret N` with a positive count — the callee popping its own
/// arguments, a discipline Microsoft x64 never spells — or an
/// `add rsp, N` in the instruction right after a call whose count does
/// not free the prologue's own allocation. An add that frees exactly
/// what the prologue subtracted is the frame teardown the convention
/// itself emits before a bare `ret`, and an add anywhere else is
/// bookkeeping; neither contradicts the shape.
fn spells_cleanup(rows: &[&str], prologue_bytes: u64) -> bool {
    for row in rows {
        let (mnemonic, operand_text) = split_instruction(instruction(row));
        if mnemonic.eq_ignore_ascii_case("ret")
            && operand_text.split_whitespace().count() == 1
            && declared_count(operand_text).is_some()
        {
            return true;
        }
    }
    for (call, next) in rows.iter().zip(rows.iter().skip(1)) {
        if !split_instruction(instruction(call))
            .0
            .eq_ignore_ascii_case("call")
        {
            continue;
        }
        let (mnemonic, operand_text) = split_instruction(instruction(next));
        if !mnemonic.eq_ignore_ascii_case("add") {
            continue;
        }
        let parts = operands(operand_text);
        if parts.len() == 2
            && parts[0].eq_ignore_ascii_case("rsp")
            && declared_count(parts[1]).is_some_and(|count| count != prologue_bytes)
        {
            return true;
        }
    }
    false
}

// ============================================================
// Detector
// ============================================================

/// Calling-convention analysis over one function's Microsoft-x64 shapes.
///
/// The detector is stateless: every reading comes from the listing text
/// it is handed, so one detector serves an entire scan. It fetches
/// nothing itself — the engine's single listing read reaches it through
/// the machine-class dispatch in [`crate::stack_discipline`], which
/// routes only `rsp`-spelled listings here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X64ShapeDetector;

impl X64ShapeDetector {
    /// A detector with the full listing-borne reading set.
    pub fn new() -> Self {
        Self
    }

    /// The Microsoft-x64 reading one function's machine listing carries,
    /// keyed by the function whose listing it is and evidenced by the
    /// prologue line that allocates the shadow space.
    ///
    /// The reading needs all three shape features — the shadow-space
    /// prologue, an argument register spelled in the listing, and no
    /// cleanup anywhere the convention never leaves one — and yields
    /// nothing when any feature is missing or contradicted. An empty
    /// listing yields nothing.
    pub fn from_listing(&self, function: &str, listing: &str) -> Vec<InferredType> {
        let rows: Vec<&str> = listing
            .lines()
            .map(str::trim)
            .filter(|row| !row.is_empty())
            .collect();
        let Some((evidence, prologue_bytes)) = shadow_space(&rows) else {
            return Vec::new();
        };
        if !ARGUMENT_REGISTERS
            .iter()
            .any(|register| spells_register(listing, register))
        {
            return Vec::new();
        }
        if spells_cleanup(&rows, prologue_bytes) {
            return Vec::new();
        }
        vec![convention_record(
            function,
            CallingConvention::MicrosoftX64,
            InferenceMethod::X64Shape,
            X64_SHAPE_CONFIDENCE,
            evidence,
        )]
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InferredConvention;
    use calxgloss_types::Confidence;

    /// The convention record inside the union, for asserting against.
    fn convention(inference: &InferredType) -> &InferredConvention {
        match inference {
            InferredType::Convention(record) => record,
            other => panic!("expected a convention record, got {other:?}"),
        }
    }

    /// A canned `rsp`-spelled x64 function showing the whole shape: the
    /// prologue subtracts `0x28` — the 32-byte home region rounded to
    /// the mandatory alignment — the callee homes its register
    /// arguments into it, and the `add rsp, 0x28` right before the bare
    /// `ret` frees exactly what the prologue took: the frame teardown
    /// the convention itself emits, not a cleanup. Rows carry the
    /// engine's own spelling: an address column, then uppercase SLEIGH
    /// mnemonics with `0x` hex operands.
    fn shape_listing() -> String {
        "140001000  SUB RSP, 0x28\n\
         140001007  MOV [RSP+0x8], RCX\n\
         14000100c  MOV [RSP+0x10], RDX\n\
         140001011  CALL FUN_1800412a0\n\
         140001016  ADD RSP, 0x28\n\
         14000101a  RET"
            .to_string()
    }

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = X64ShapeDetector::new();
        assert_eq!(detector, X64ShapeDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven over a scan's listing reads through the
        // dispatch, so sharing one by reference across tasks must stay
        // sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<X64ShapeDetector>();
    }

    // ---- the shape reading ----

    #[test]
    fn a_shadow_space_prologue_with_register_arguments_reads_microsoft_x64() {
        // All three features hold: the prologue allocates the home
        // region, the listing spells the argument registers, and no
        // cleanup stands anywhere — the function reads Microsoft x64 at
        // the shape-only band, with the prologue line as the evidence.
        let readings = X64ShapeDetector::new().from_listing("FUN_18003e750", &shape_listing());
        assert_eq!(readings.len(), 1);
        let record = convention(&readings[0]);
        assert_eq!(record.function, "FUN_18003e750");
        assert_eq!(record.convention, CallingConvention::MicrosoftX64);
        assert_eq!(record.method, InferenceMethod::X64Shape);
        assert_eq!(record.confidence, Confidence::new(X64_SHAPE_CONFIDENCE));
        assert_eq!(record.evidence, "140001000  SUB RSP, 0x28");
    }

    #[test]
    fn a_leaf_that_homes_its_arguments_reads_microsoft_x64() {
        // A function that never calls still shows the shape: the prologue
        // allocates the home region and the callee homes its arguments
        // into it before a bare ret. With no call in the listing, the
        // whole body is prologue.
        let listing = "140001000  SUB RSP, 0x20\n\
                       140001007  MOV [RSP+0x8], RCX\n\
                       14000100c  RET";
        let readings = X64ShapeDetector::new().from_listing("FUN_x", listing);
        assert_eq!(readings.len(), 1);
        assert_eq!(
            convention(&readings[0]).evidence,
            "140001000  SUB RSP, 0x20"
        );
    }

    // ---- the guards ----

    #[test]
    fn a_prologue_below_the_shadow_space_reads_nothing() {
        // A frame smaller than the 32-byte home region allocates no
        // shadow space, and a listing with no `sub rsp` at all allocates
        // nothing: neither shows the shape.
        let detector = X64ShapeDetector::new();
        let small = "140001000  SUB RSP, 0x8\n\
                     140001007  MOV [RSP+0x8], RCX\n\
                     14000100c  RET";
        assert!(detector.from_listing("FUN_x", small).is_empty());
        let no_sub = "140001000  MOV RCX, RDX\n\
                      140001003  CALL FUN_1800412a0\n\
                      140001008  RET";
        assert!(detector.from_listing("FUN_x", no_sub).is_empty());
    }

    #[test]
    fn a_sub_rsp_after_the_first_call_is_no_prologue_shape() {
        // The allocation has to ride the prologue — the region before
        // the first call, where a compiler emits the frame setup. A
        // `sub rsp, 0x28` in the middle of the body is dynamic frame
        // bookkeeping, not the convention's home region.
        let listing = "140001000  MOV [RSP+0x8], RCX\n\
                       140001007  CALL FUN_1800412a0\n\
                       14000100c  SUB RSP, 0x28\n\
                       140001010  RET";
        assert!(
            X64ShapeDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn a_listing_that_spells_no_argument_register_reads_nothing() {
        // The home region only means the convention when there are
        // register arguments to home: a void function with a large
        // frame shows the allocation but no RCX, RDX, R8, or R9, and
        // yields no reading rather than a guess.
        let listing = "140001000  SUB RSP, 0x40\n\
                       140001007  CALL FUN_1800412a0\n\
                       14000100c  ADD RSP, 0x40\n\
                       140001010  RET";
        assert!(
            X64ShapeDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    // ---- the cleanup contradiction ----

    #[test]
    fn a_callee_epilogue_that_pops_contradicts_the_shape() {
        // A `ret N` with a positive count states the callee pops its own
        // arguments — a discipline Microsoft x64 never spells — so the
        // listing contradicts its own shadow-space prologue and yields
        // no reading.
        let listing = "140001000  SUB RSP, 0x28\n\
                       140001007  MOV [RSP+0x8], RCX\n\
                       14000100c  RET 0x20";
        assert!(
            X64ShapeDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn a_caller_cleanup_after_a_call_contradicts_the_shape() {
        // An `add rsp, 0x20` right after a call frees a different count
        // than the prologue took: that is a caller popping arguments,
        // the cleanup the convention leaves to the frame — the shape is
        // contradicted and yields no reading.
        let listing = "140001000  SUB RSP, 0x28\n\
                       140001007  MOV RCX, RDX\n\
                       14000100a  CALL FUN_1800412a0\n\
                       14000100f  ADD RSP, 0x20\n\
                       140001013  RET";
        assert!(
            X64ShapeDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn a_teardown_that_frees_the_prologue_is_no_cleanup() {
        // The commonest real x64 tail — call, then `add rsp` freeing
        // exactly the prologue's allocation, then a bare `ret` — is the
        // frame teardown the convention itself emits, not a cleanup:
        // the reading stands even though the add sits right after the
        // call.
        let readings = X64ShapeDetector::new().from_listing("FUN_x", &shape_listing());
        assert_eq!(readings.len(), 1);
        assert_eq!(
            convention(&readings[0]).convention,
            CallingConvention::MicrosoftX64
        );
    }

    #[test]
    fn an_add_that_stands_elsewhere_is_bookkeeping() {
        // Only the instruction right after a call can spell a caller
        // cleanup; an `add rsp` elsewhere in the body — even a count
        // that does not match the prologue — is stack bookkeeping and
        // contradicts nothing.
        let listing = "140001000  SUB RSP, 0x28\n\
                       140001007  MOV [RSP+0x8], RCX\n\
                       14000100c  ADD RSP, 0x8\n\
                       140001010  CALL FUN_1800412a0\n\
                       140001015  RET";
        let readings = X64ShapeDetector::new().from_listing("FUN_x", listing);
        assert_eq!(readings.len(), 1);
    }

    #[test]
    fn an_empty_listing_reads_nothing() {
        // The seam's default answers empty for a source that has not
        // opted in, and a function with nothing listed simply goes
        // unrecorded.
        assert!(X64ShapeDetector::new().from_listing("FUN_x", "").is_empty());
    }
}
