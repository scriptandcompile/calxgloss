//! Calling-convention detection from the machine listing: the x86
//! stack-discipline channels.
//!
//! The [`crate::convention`] detector reads how a function is called
//! from its *name*. This detector reads it from the function's
//! *instructions* — the seam's per-function disassembly text (issue
//! #245). The 32-bit stack discipline the listing spells turns that
//! text into convention records:
//!
//! - **A callee epilogue that cleans up its own arguments.** A `ret N`
//!   with a positive byte count states the callee-pops discipline
//!   outright, so the function is called stdcall. The epilogue line
//!   itself is the evidence, at the exact-epilogue band
//!   (`EPILOGUE_CONFIDENCE`).
//! - **A caller that cleans up after a call.** An `add esp, N` in the
//!   instruction right after a direct call site naming a callee means
//!   the caller pops. That callee is called cdecl. The cleanup line is
//!   the evidence, at the caller-cleanup band (`CALLER_CLEANUP_CONFIDENCE`).
//!
//! The whole family keys on the stack register spelled in the listing
//! itself, not on any new metadata. An `esp`-spelled listing is the
//! 32-bit class; an `rsp`-spelled one is the 64-bit class. The two
//! families never read the other's class: a 64-bit listing never
//! produces a 32-bit reading. A listing that spells no stack register
//! keys no family, and it yields no reading rather than a guess. This
//! module's `machine_class` function is the single dispatch that routes
//! both listing-borne families: the x64 shape family (shadow-space
//! prologue, register-first arguments, no cleanup) lives in
//! [`crate::x64_shape`] and is routed from
//! [`StackDisciplineDetector::from_listing`] (issue #248). The
//! row-shape helpers below are `pub(crate)` so that family parses the
//! same listing shape.
//!
//! A call site whose operand is an address (`CALL 0x140002490`, the
//! analysis engine's own spelling) or an indirect register or memory
//! operand names no callee to key a record by, and yields no reading.
//! Recording a detected callee convention at its call sites is the job
//! of the cross-function corroboration pass, in [`crate::corroboration`]
//! (issue #249).

use crate::convention::convention_record;
use crate::types::{CallingConvention, InferenceMethod, InferredType};

/// Evidence confidence of the exact-epilogue band: a `ret N` states the
/// callee's own cleanup outright — an exact spelling of the discipline.
/// That puts the reading with the name-borne bands, above this family's
/// shape-based readings. But the epilogue names only who pops, not
/// which callee-pops convention, so it stays below the mangled letter
/// (90) and the `@N` decoration (85), which spell the convention
/// itself.
const EPILOGUE_CONFIDENCE: u8 = 80;

/// Evidence confidence of the caller-cleanup band: an `add esp, N`
/// right after a call is the direct mark of a caller that pops, so the
/// callee reads cdecl. That is solid listing evidence, one band below
/// the exact epilogue — one call site shows the caller's habit rather
/// than the callee's own epilogue. Nothing self-upgrades, and the
/// cross-function corroboration pass (issue #249) does not raise this
/// band: it raises only epilogue and x64-shape readings. A cleanup
/// reading stands until a stronger record for the same callee wins
/// resolution.
const CALLER_CLEANUP_CONFIDENCE: u8 = 70;

/// The general-purpose x86 register names an indirect call can spell as
/// its operand; none of them is ever a callee.
const REGISTERS: &[&str] = &[
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ax", "bx", "cx", "dx", "si", "di",
    "bp", "sp", "al", "bl", "cl", "dl", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

/// Which machine class a listing spells, keyed on the stack register the
/// listing itself names. The x86 family reads only the 32-bit class;
/// the x64 shape family in [`crate::x64_shape`] reads only the 64-bit
/// one; a listing spelling neither stack register keys no family at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineClass {
    X86,
    X64,
    Unknown,
}

fn machine_class(listing: &str) -> MachineClass {
    if spells_register(listing, "rsp") {
        MachineClass::X64
    } else if spells_register(listing, "esp") {
        MachineClass::X86
    } else {
        MachineClass::Unknown
    }
}

/// Whether any token of the listing spells `register`: tokens split on
/// everything that is not alphanumeric, so `[ESP+0x4]` spells `ESP`
/// while `RSI` never spells `RSP`. Shared with [`crate::x64_shape`].
pub(crate) fn spells_register(listing: &str, register: &str) -> bool {
    listing
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token.eq_ignore_ascii_case(register))
}

/// The instruction text of one listing row. The analysis engine's own
/// rows use an address column — `{:08x}  MNEMONIC operands` — and a
/// canned listing spells the same shape. The column is stripped when
/// the row opens with a hex run of address length; a row without one
/// is already just the instruction. (Address length, so an `ADD` row
/// with no column is not mistaken for one: `ADD` is three hex-looking
/// letters, not an address.) Shared with [`crate::x64_shape`].
pub(crate) fn instruction(row: &str) -> &str {
    match row.split_once("  ") {
        Some((head, rest)) if head.len() >= 6 && head.bytes().all(|b| b.is_ascii_hexdigit()) => {
            rest.trim()
        }
        _ => row.trim(),
    }
}

/// `MNEMONIC operands` split the way the analysis engine spells them:
/// the first token is the mnemonic, the rest the operand text. Shared
/// with [`crate::x64_shape`].
pub(crate) fn split_instruction(text: &str) -> (&str, &str) {
    let mut words = text.splitn(2, char::is_whitespace);
    (
        words.next().unwrap_or(""),
        words.next().unwrap_or("").trim(),
    )
}

/// The operands of one instruction as the analysis engine spells them,
/// comma-separated; a canned listing that separates with plain spaces
/// reads the same. Shared with [`crate::x64_shape`].
pub(crate) fn operands(operand_text: &str) -> Vec<&str> {
    if operand_text.contains(',') {
        operand_text.split(',').map(str::trim).collect()
    } else {
        operand_text.split_whitespace().collect()
    }
}

/// The byte count a numeric operand declares — `0xC` hex or plain
/// decimal — and only when it is positive: a `ret 0` cleans nothing,
/// and a register or memory operand spells no count. Shared with
/// [`crate::x64_shape`].
pub(crate) fn declared_count(text: &str) -> Option<u64> {
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix)
        .ok()
        .filter(|count| *count > 0)
}

/// The callee a direct call site names: one identifier-like operand
/// that is not an address and not a register. The analysis engine's own
/// rows call through an address (`CALL 0x140002490`) — that names
/// nothing a record can be keyed by — and an indirect call through a
/// register or a memory operand names nothing either. Shared with
/// [`crate::corroboration`].
pub(crate) fn called_name(operand_text: &str) -> Option<&str> {
    let target = operand_text.trim();
    let names_a_callee = !target.is_empty()
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '?'))
        && !target.starts_with("0x")
        && !target.bytes().all(|b| b.is_ascii_hexdigit())
        && !REGISTERS.iter().any(|r| target.eq_ignore_ascii_case(r));
    names_a_callee.then_some(target)
}

// ============================================================
// Detector
// ============================================================

/// Calling-convention analysis over one function's machine listing.
///
/// The detector is stateless: every reading comes from the listing
/// text it is handed, so one detector serves an entire scan. It fetches
/// nothing itself — the scan hands it each listed function's
/// disassembly text, read once inside the breaker-gated window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackDisciplineDetector;

impl StackDisciplineDetector {
    /// A detector with the full listing-borne reading set.
    pub fn new() -> Self {
        Self
    }

    /// The convention readings one function's machine listing yields —
    /// whichever family the listing's own stack register keys. The
    /// 32-bit readings are keyed by the function whose listing it is,
    /// except a caller-cleanup reading, which is keyed by the callee
    /// named at the cleaned-up call site; the x64 shape reading is
    /// keyed by the function whose listing it is.
    ///
    /// The evidence of every reading is the listing line it came from,
    /// address column and all, so the claim can be checked against the
    /// listing itself. An empty listing, and a listing whose stack
    /// register keys no readable family, yield no readings.
    pub fn from_listing(&self, function: &str, listing: &str) -> Vec<InferredType> {
        match machine_class(listing) {
            MachineClass::X86 => self.x86_readings(function, listing),
            // One listing read feeds both families. An rsp-spelled
            // listing goes to the 64-bit shapes and never to the x86
            // channels. A listing that spells no stack register keys
            // no family at all: no reading rather than a guess about
            // which machine it is.
            MachineClass::X64 => {
                crate::x64_shape::X64ShapeDetector::new().from_listing(function, listing)
            }
            MachineClass::Unknown => Vec::new(),
        }
    }

    /// The 32-bit family: the callee's own epilogue cleanup, and the
    /// caller-side cleanup at each call site that names its callee.
    fn x86_readings(&self, function: &str, listing: &str) -> Vec<InferredType> {
        let rows: Vec<&str> = listing
            .lines()
            .map(str::trim)
            .filter(|row| !row.is_empty())
            .collect();
        let mut readings = Vec::new();

        // The exact epilogue: the first `ret N` with a positive count
        // states this function's own cleanup outright. A function can
        // have several epilogues. The first one seen yields the
        // reading — the same first-seen rule that settles a tie in
        // resolution.
        for row in &rows {
            let (mnemonic, operand_text) = split_instruction(instruction(row));
            if mnemonic.eq_ignore_ascii_case("ret")
                && operand_text.split_whitespace().count() == 1
                && declared_count(operand_text).is_some()
            {
                readings.push(convention_record(
                    function,
                    CallingConvention::Stdcall,
                    InferenceMethod::CalleeEpilogue,
                    EPILOGUE_CONFIDENCE,
                    row,
                ));
                break;
            }
        }

        // The caller-side cleanup: an `add esp, N` in the instruction
        // right after a direct call. That is the shape a compiler emits
        // when the caller pops, so the callee named at that site reads
        // cdecl.
        for (call, cleanup) in rows.iter().zip(rows.iter().skip(1)) {
            let (call_mnemonic, call_operand) = split_instruction(instruction(call));
            if !call_mnemonic.eq_ignore_ascii_case("call") {
                continue;
            }
            let Some(callee) = called_name(call_operand) else {
                continue;
            };
            let (cleanup_mnemonic, cleanup_operands) = split_instruction(instruction(cleanup));
            if !cleanup_mnemonic.eq_ignore_ascii_case("add") {
                continue;
            }
            let parts = operands(cleanup_operands);
            if parts.len() == 2
                && parts[0].eq_ignore_ascii_case("esp")
                && declared_count(parts[1]).is_some()
            {
                readings.push(convention_record(
                    callee,
                    CallingConvention::Cdecl,
                    InferenceMethod::CallerCleanup,
                    CALLER_CLEANUP_CONFIDENCE,
                    cleanup,
                ));
            }
        }

        readings
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

    /// A canned `esp`-spelled epilogue: a frame setup, then a `ret`
    /// that pops twelve argument bytes — the callee cleans up its own
    /// stack. The rows use the analysis engine's own spelling: an
    /// address column, then uppercase SLEIGH mnemonics with `0x` hex
    /// operands.
    fn epilogue_listing() -> String {
        "00401000  PUSH EBP\n\
         00401001  MOV EBP, ESP\n\
         00401003  SUB ESP, 0x10\n\
         00401006  POP EBP\n\
         00401007  RET 0xC"
            .to_string()
    }

    /// A canned `esp`-spelled caller: two pushes, a direct call naming
    /// its callee, then the caller popping the arguments it pushed.
    fn caller_listing() -> String {
        "00401100  PUSH EBP\n\
         00401101  MOV EBP, ESP\n\
         00401103  PUSH 0x0\n\
         00401105  PUSH 0x1\n\
         00401107  CALL FUN_1800412a0\n\
         0040110c  ADD ESP, 0x8\n\
         0040110f  POP EBP\n\
         00401110  RET"
            .to_string()
    }

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = StackDisciplineDetector::new();
        assert_eq!(detector, StackDisciplineDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven over a scan's listing reads, so
        // sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StackDisciplineDetector>();
    }

    // ---- the callee epilogue ----

    #[test]
    fn an_epilogue_that_pops_its_arguments_reads_stdcall() {
        // `ret 0xC` in an esp-spelled listing states the callee's own
        // cleanup outright. The reading sits at the exact-epilogue
        // band, with the epilogue line itself as the evidence.
        let readings =
            StackDisciplineDetector::new().from_listing("FUN_18003e750", &epilogue_listing());
        assert_eq!(readings.len(), 1);
        let record = convention(&readings[0]);
        assert_eq!(record.function, "FUN_18003e750");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::CalleeEpilogue);
        assert_eq!(record.confidence, Confidence::new(EPILOGUE_CONFIDENCE));
        assert_eq!(record.evidence, "00401007  RET 0xC");
    }

    #[test]
    fn a_bare_ret_and_a_zero_count_spell_no_cleanup() {
        // A plain `ret` pops nothing, and `ret 0` declares a cleanup of
        // zero bytes — neither is a callee that cleans up arguments.
        let detector = StackDisciplineDetector::new();
        for tail in ["RET", "RET 0x0"] {
            let listing = format!("00401000  MOV EBP, ESP\n00401007  {tail}");
            assert!(
                detector.from_listing("FUN_x", &listing).is_empty(),
                "{tail} spells no cleanup"
            );
        }
    }

    #[test]
    fn several_epilogues_land_one_reading_on_the_first() {
        // A function can have several epilogues. The first one seen
        // yields the reading — the same first-seen rule that settles an
        // equal-confidence tie in resolution.
        let listing = "00401000  MOV EBP, ESP\n\
                       00401003  RET 0x4\n\
                       00401005  RET 0x8";
        let readings = StackDisciplineDetector::new().from_listing("FUN_x", listing);
        assert_eq!(readings.len(), 1);
        assert_eq!(convention(&readings[0]).evidence, "00401003  RET 0x4");
    }

    // ---- the caller-side cleanup ----

    #[test]
    fn a_caller_that_pops_after_a_named_call_reads_cdecl_for_the_callee() {
        // `add esp, 0x8` right after `call FUN_1800412a0`: the caller
        // pops the arguments it pushed, so the callee named at that
        // site is called cdecl — keyed by the callee, evidenced by the
        // cleanup line.
        let readings =
            StackDisciplineDetector::new().from_listing("FUN_18003ab00", &caller_listing());
        assert_eq!(readings.len(), 1);
        let record = convention(&readings[0]);
        assert_eq!(record.function, "FUN_1800412a0");
        assert_eq!(record.convention, CallingConvention::Cdecl);
        assert_eq!(record.method, InferenceMethod::CallerCleanup);
        assert_eq!(
            record.confidence,
            Confidence::new(CALLER_CLEANUP_CONFIDENCE)
        );
        assert_eq!(record.evidence, "0040110c  ADD ESP, 0x8");
    }

    #[test]
    fn the_cleanup_only_reads_when_it_follows_the_call() {
        // The reading is the shape a compiler emits when the caller
        // pops: the add in the instruction right after the call. An
        // add that stands elsewhere in the body — before the call, or
        // after some other instruction — is stack bookkeeping, not a
        // call-site cleanup.
        let detector = StackDisciplineDetector::new();
        let reordered = "00401100  MOV EBP, ESP\n\
                         00401103  ADD ESP, 0x8\n\
                         00401107  CALL FUN_1800412a0\n\
                         0040110c  RET";
        assert!(
            detector
                .from_listing("FUN_x", reordered)
                .iter()
                .all(|reading| convention(reading).method != InferenceMethod::CallerCleanup)
        );
        let not_adjacent = "00401100  MOV EBP, ESP\n\
                            00401103  CALL FUN_1800412a0\n\
                            00401108  NOP\n\
                            00401109  ADD ESP, 0x8\n\
                            0040110c  RET";
        assert!(
            detector
                .from_listing("FUN_x", not_adjacent)
                .iter()
                .all(|reading| convention(reading).method != InferenceMethod::CallerCleanup)
        );
    }

    #[test]
    fn an_indirect_or_address_call_site_names_no_callee() {
        // The analysis engine's own rows call through an address. An
        // indirect call runs through a register or memory operand.
        // None of them names a callee a record could be keyed by, so
        // the cleanup yields no reading rather than a record keyed by
        // an address or a register.
        let detector = StackDisciplineDetector::new();
        for call in [
            "CALL 0x401100",
            "CALL EAX",
            "CALL DWORD PTR [EAX+0x4]",
            "CALL ESP",
        ] {
            let listing = format!(
                "00401100  MOV EBP, ESP\n\
                 00401103  {call}\n\
                 00401108  ADD ESP, 0x8\n\
                 0040110c  RET"
            );
            assert!(
                detector.from_listing("FUN_x", &listing).is_empty(),
                "{call} names no callee"
            );
        }
    }

    // ---- the machine-class keying ----

    #[test]
    fn an_rsp_spelled_listing_yields_no_32_bit_reading() {
        // The same cleanup shapes spelled with the 64-bit stack
        // register — even a `ret N` — produce no 32-bit reading. The
        // family keys on the register the listing itself spells, so
        // the two families never read the other's class. The x64
        // family stays silent on this listing too: the cleanup
        // contradicts its shape and no argument register is spelled,
        // so the dispatch records nothing at all.
        let listing = "140001000  SUB RSP, 0x28\n\
                       140001007  CALL FUN_1800412a0\n\
                       14000100c  ADD RSP, 0x20\n\
                       140001010  RET 0x20";
        assert!(
            StackDisciplineDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn an_esp_spelled_listing_yields_no_x64_reading() {
        // The dispatch keys the families from both sides: a 32-bit
        // listing spelling the x64 shape's features — a 0x28 sub, an
        // argument register, no cleanup — still keys the x86 family,
        // which reads no discipline in it, and the x64 family never
        // fires on an esp-spelled listing.
        let listing = "00401000  SUB ESP, 0x28\n\
                       00401007  MOV [ESP], RCX\n\
                       0040100a  CALL FUN_1800412a0\n\
                       0040100f  RET";
        assert!(
            StackDisciplineDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn the_dispatch_routes_an_rsp_spelled_listing_to_the_x64_family() {
        // The x64 shape family is routed through this dispatch. An
        // rsp-spelled listing showing the full shape produces its
        // Microsoft-x64 reading through the same entry point as the
        // 32-bit channels.
        let listing = "140001000  SUB RSP, 0x28\n\
                       140001007  MOV [RSP+0x8], RCX\n\
                       14000100c  RET";
        let readings = StackDisciplineDetector::new().from_listing("FUN_x", listing);
        assert_eq!(readings.len(), 1);
        assert_eq!(
            convention(&readings[0]).convention,
            CallingConvention::MicrosoftX64
        );
        assert_eq!(
            convention(&readings[0]).evidence,
            "140001000  SUB RSP, 0x28"
        );
    }

    #[test]
    fn a_listing_that_spells_no_stack_register_reads_nothing() {
        // A listing that spells neither stack register keys no family:
        // even a `ret N` stands unclassified, and the detector yields
        // no reading rather than guessing the machine.
        let listing = "00401000  XOR EAX, EAX\n00401002  RET 0xC";
        assert!(
            StackDisciplineDetector::new()
                .from_listing("FUN_x", listing)
                .is_empty()
        );
    }

    #[test]
    fn an_empty_listing_reads_nothing() {
        // The seam's default answers empty for a source that has not
        // opted in, and a function with nothing listed simply goes
        // unrecorded.
        assert!(
            StackDisciplineDetector::new()
                .from_listing("FUN_x", "")
                .is_empty()
        );
    }
}
