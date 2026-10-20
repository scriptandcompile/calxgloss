//! Calling-convention detection across functions: corroboration and
//! call-site conventions.
//!
//! Every other convention channel reads one body's word — an epilogue,
//! a cleanup, a name. [`ConventionCorroborator`] is the post-inline
//! pass that trusts *agreement* above any single reading (the
//! flag-family precedent, issue #249), over exactly what the scan
//! already holds: the surviving per-function convention records and
//! the disassembly listings read during the walk. It fetches nothing —
//! no extra decompiles, no extra listing reads.
//!
//! Two families corroborate:
//!
//! - **the callee-pops family**: a callee epilogue (`ret N`), the
//!   absence of caller-side cleanup at every call site naming that
//!   callee in the kept listings, and the declared argument bytes (the
//!   `@N` decoration on the callee's name) all agreeing on stdcall
//!   raises the reading to [`CORROBORATED_EPILOGUE_CONFIDENCE`] —
//!   above every single reading, since three independent spellings
//!   agree;
//! - **the x64 family**: a callee's shape reading corroborated by
//!   call sites in `rsp`-spelled caller listings that show no cleanup
//!   after the call — the discipline Microsoft x64 never breaks —
//!   raises it to [`CORROBORATED_X64_CONFIDENCE`], above the
//!   shape-only tier but still below every exact spelling.
//!
//! A contradicted family never bumps: one caller popping after a call
//! to an epilogue-read callee means the readings disagree, and the
//! resolution rule leaves the higher-confidence reading standing.
//!
//! On top of the bumps, every detected callee convention lands a
//! **call-site record** in each caller whose listing calls it: the
//! record is keyed by the caller and names the callee — one view per
//! caller and callee, at the first site naming it — so the caller's
//! view of its callee matches the callee's own record: the same
//! convention, the callee's own confidence. A caller's extern spelling
//! for the callee can then be checked against it. Records are emitted
//! in listing order, so two scans of one program diff cleanly.

use std::collections::HashMap;

use crate::convention::{convention_record, declared_argument_bytes};
use crate::stack_discipline::{
    called_name, declared_count, instruction, operands, spells_register, split_instruction,
};
use crate::types::{CallingConvention, InferenceMethod, InferredConvention, InferredType};
use crate::x64_shape::shadow_space;

/// Confidence of a corroborated callee-pops reading: the epilogue, the
/// absence of caller-side cleanup at its sites, and the declared
/// argument bytes agree across functions, so the agreement outranks
/// every single reading — above the mangled letter (90) and the `@N`
/// decoration (85), the flag-family precedent taken to the top of the
/// scale.
const CORROBORATED_EPILOGUE_CONFIDENCE: u8 = 92;

/// Confidence of a corroborated x64 shape reading: the shape plus
/// clean call sites in 64-bit callers is agreement across functions,
/// so it sits above the shape-only tier (65) — the flag family's
/// +10 — but a shape is still never a spelling, so it stays below
/// every exact channel.
const CORROBORATED_X64_CONFIDENCE: u8 = 75;

/// One direct call site naming `callee` in a listing: the call row
/// (the record's evidence) and the instruction row right after it, if
/// any. Rows are pairwise-adjacent exactly as the stack-discipline
/// reader sees them.
/// The listing's rows, trimmed and with the blanks dropped — exactly the
/// shape the listing-borne detectors read.
fn rows(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .map(str::trim)
        .filter(|row| !row.is_empty())
        .collect()
}

/// Every call site in every kept listing, grouped per listing by the
/// callee name the call row names, sites in row order. The corroboration
/// pass asks "does this listing call that callee, and what follows the
/// call" once per (listing, record) pair; answering each question by
/// re-splitting and re-parsing the whole listing is quadratic in the
/// function count and hung the scan on a 7,267-function 32-bit image
/// (the 2026-10-20 LaunchPad.exe incident — thousands of `ret N`
/// epilogue records × thousands of listings). Reading each listing once
/// here makes the whole pass linear in the disassembly text.
fn call_index<'a>(listings: &[(&'a str, &'a str)]) -> Vec<HashMap<&'a str, Vec<(&'a str, Option<&'a str>)>>> {
    listings
        .iter()
        .map(|(_, listing)| {
            let rows: Vec<&str> = rows(listing);
            let mut by_callee: HashMap<&str, Vec<(&str, Option<&str>)>> = HashMap::new();
            for (index, row) in rows.iter().enumerate() {
                let (mnemonic, operand) = split_instruction(instruction(row));
                if mnemonic.eq_ignore_ascii_case("call")
                    && let Some(name) = called_name(operand)
                {
                    by_callee
                        .entry(name)
                        .or_default()
                        .push((*row, rows.get(index + 1).copied()));
                }
            }
            by_callee
        })
        .collect()
}

/// Whether the row right after a call is a caller-side stack cleanup —
/// `add esp, N` / `add rsp, N` with a positive count — for the stack
/// register the caller's own listing spells. In a 64-bit caller an add
/// freeing exactly the prologue's own allocation (`frame_bytes`) is the
/// frame teardown the convention itself emits, not a cleanup; the
/// 32-bit family passes `None`, where every post-call add pops for the
/// callee.
fn cleans_up(next: Option<&str>, register: &str, frame_bytes: Option<u64>) -> bool {
    let Some(row) = next else { return false };
    let (mnemonic, operand_text) = split_instruction(instruction(row));
    if !mnemonic.eq_ignore_ascii_case("add") {
        return false;
    }
    let parts = operands(operand_text);
    parts.len() == 2
        && parts[0].eq_ignore_ascii_case(register)
        && declared_count(parts[1]).is_some_and(|count| Some(count) != frame_bytes)
}

/// The byte count a callee-epilogue record's evidence line declares —
/// the record came from a `ret N` row, so re-reading the count from
/// the kept evidence is exact.
fn epilogue_bytes(record: &InferredConvention) -> Option<u64> {
    let (mnemonic, operand_text) = split_instruction(instruction(&record.evidence));
    mnemonic
        .eq_ignore_ascii_case("ret")
        .then(|| declared_count(operand_text))
        .flatten()
}

/// Calling-convention corroboration over a scan's surviving readings
/// and kept listings.
///
/// The pass is stateless: every record comes from the readings and
/// listings it is handed, so one corroborator serves an entire scan.
/// It fetches nothing itself — the engine hands it the resolved
/// per-function convention records and the disassembly text it
/// already read, keeping the scan at one listing read per function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConventionCorroborator;

impl ConventionCorroborator {
    /// A corroborator with no state: the readings and listings come in
    /// at call time.
    pub fn new() -> Self {
        Self
    }

    /// The corroborated readings and call-site records for one scan.
    ///
    /// `conventions` are the scan's resolved records (inline survivors
    /// and anything appended before this pass); only the per-function
    /// readings — those with no `callee` — seed the pass. `listings`
    /// are the kept disassembly texts in listing order, exactly as
    /// the walk read them.
    ///
    /// The output is ordered: corroborated bumps first, in the order
    /// their callee's reading appeared, then the call-site records in
    /// listing order — caller by caller, one view per callee, evidenced
    /// by the first site naming it — so two scans of one program diff
    /// cleanly. Where a bump lands, the callee's call-site records
    /// carry the bumped convention and confidence, matching the callee's
    /// own surviving record.
    pub fn corroborate(
        &self,
        conventions: &[InferredType],
        listings: &[(&str, &str)],
    ) -> Vec<InferredType> {
        // One read of the kept disassembly text, answering every
        // "does this caller call that callee, and what follows the
        // call" the pass asks below.
        let index = call_index(listings);

        // The bumps, in the order the callee's reading appeared in the
        // scan — the scan order is listing order, so the output is
        // deterministic whatever the map's iteration does.
        let mut bumped: HashMap<&str, InferredType> = HashMap::new();
        let mut bumps: Vec<InferredType> = Vec::new();
        // The x64 facts (does the caller spell `rsp`, what does its
        // prologue allocate) only matter when some reading is an x64
        // shape; on an esp-spelled program they are never computed.
        let x64_shapes = conventions.iter().any(|inference| {
            matches!(
                inference,
                InferredType::Convention(record)
                    if record.method == InferenceMethod::X64Shape && record.callee.is_none()
            )
        });
        let x64_facts: Option<Vec<(bool, Option<u64>)>> = x64_shapes.then(|| {
            listings
                .iter()
                .map(|(_, listing)| {
                    (
                        spells_register(listing, "rsp"),
                        shadow_space(&rows(listing)).map(|(_, bytes)| bytes),
                    )
                })
                .collect()
        });
        for inference in conventions {
            let InferredType::Convention(record) = inference else {
                continue;
            };
            if record.callee.is_some() {
                continue;
            }
            let reading = match record.method {
                InferenceMethod::CalleeEpilogue => self.epilogue_agrees(record, listings, &index),
                InferenceMethod::X64Shape => {
                    self.x64_agrees(record, listings, &index, x64_facts.as_ref().expect("computed with x64 shapes"))
                }
                _ => None,
            };
            if let Some(reading) = reading {
                bumps.push(reading.clone());
                bumped.insert(record.function.as_str(), reading);
            }
        }

        // The call-site records: each kept listing is a caller's view
        // of every detected callee it calls directly, carrying the
        // callee's final convention and confidence. One view per
        // (caller, callee) pair — the pair is the record's target, so
        // a second site naming the same callee adds nothing — evidenced
        // by the first site that names it.
        //
        // The naive shape probes every record against every listing;
        // instead each listing contributes exactly the records its own
        // call rows name, visited in record order so the output is
        // identical to that naive walk.
        let mut records: Vec<&InferredConvention> = Vec::new();
        let mut record_of: HashMap<&str, Vec<usize>> = HashMap::new();
        for inference in conventions {
            let InferredType::Convention(record) = inference else {
                continue;
            };
            if record.callee.is_some() {
                continue;
            }
            record_of
                .entry(record.function.as_str())
                .or_default()
                .push(records.len());
            records.push(record);
        }
        let mut sites: Vec<InferredType> = Vec::new();
        for (li, (caller, _)) in listings.iter().enumerate() {
            let called = &index[li];
            let mut matched: Vec<usize> = called
                .keys()
                .filter(|callee| *callee != caller)
                .flat_map(|callee| {
                    record_of
                        .get(callee)
                        .map(|slots| slots.as_slice())
                        .unwrap_or(&[])
                        .iter()
                        .copied()
                })
                .collect();
            matched.sort_unstable();
            for slot in matched {
                let record = records[slot];
                let final_record = bumped
                    .get(record.function.as_str())
                    .map(|bump| match bump {
                        InferredType::Convention(bumped) => bumped,
                        _ => unreachable!("a bump is a convention record"),
                    })
                    .unwrap_or(record);
                // The index only holds real call rows naming a callee,
                // and `matched` was built from its keys — the lookup
                // cannot miss, and the first site is in row order
                // exactly as the naive scan found it.
                let (row, _) = called[record.function.as_str()][0];
                sites.push(InferredType::Convention(InferredConvention {
                    function: caller.to_string(),
                    callee: Some(record.function.clone()),
                    convention: final_record.convention,
                    method: InferenceMethod::CallSiteConvention,
                    confidence: final_record.confidence,
                    evidence: row.to_string(),
                }));
            }
        }

        bumps.extend(sites);
        bumps
    }

    /// The callee-pops family: the epilogue's `ret N`, the `@N`
    /// decoration's declared bytes, and clean call sites in other
    /// functions' listings all agreeing on stdcall.
    fn epilogue_agrees(
        &self,
        record: &InferredConvention,
        listings: &[(&str, &str)],
        index: &[HashMap<&str, Vec<(&str, Option<&str>)>>],
    ) -> Option<InferredType> {
        let declared = declared_argument_bytes(&record.function)?
            .parse::<u64>()
            .ok()?;
        let epilogue = epilogue_bytes(record)?;
        if declared != epilogue {
            return None;
        }
        let mut callers: Vec<&str> = Vec::new();
        for (li, (caller, _)) in listings.iter().enumerate() {
            if *caller == record.function {
                continue;
            }
            let Some(sites) = index[li].get(record.function.as_str()) else {
                continue;
            };
            if sites.iter().any(|(_, next)| cleans_up(*next, "esp", None)) {
                return None;
            }
            callers.push(caller);
        }
        if callers.is_empty() {
            return None;
        }
        Some(convention_record(
            &record.function,
            CallingConvention::Stdcall,
            InferenceMethod::CorroboratedConvention,
            CORROBORATED_EPILOGUE_CONFIDENCE,
            &format!(
                "{}; no caller cleanup at {}; declared bytes @{declared} agrees",
                record.evidence,
                callers.join(", ")
            ),
        ))
    }

    /// The x64 family: the shape reading corroborated by call sites in
    /// `rsp`-spelled caller listings that show no cleanup after the
    /// call. An `esp`-spelled caller contradicts — its discipline is
    /// the 32-bit one the x64 convention never spells — and so does a
    /// cleanup at any site; an add freeing the caller's own prologue
    /// allocation is frame teardown, the same exception the shape
    /// detector itself honours.
    fn x64_agrees(
        &self,
        record: &InferredConvention,
        listings: &[(&str, &str)],
        index: &[HashMap<&str, Vec<(&str, Option<&str>)>>],
        x64_facts: &[(bool, Option<u64>)],
    ) -> Option<InferredType> {
        let mut callers: Vec<&str> = Vec::new();
        for (li, (caller, _)) in listings.iter().enumerate() {
            if *caller == record.function {
                continue;
            }
            let Some(sites) = index[li].get(record.function.as_str()) else {
                continue;
            };
            let (spells_rsp, frame) = x64_facts[li];
            if !spells_rsp {
                return None;
            }
            if sites.iter().any(|(_, next)| cleans_up(*next, "rsp", frame)) {
                return None;
            }
            callers.push(caller);
        }
        if callers.is_empty() {
            return None;
        }
        Some(convention_record(
            &record.function,
            CallingConvention::MicrosoftX64,
            InferenceMethod::CorroboratedConvention,
            CORROBORATED_X64_CONFIDENCE,
            &format!(
                "{}; no caller cleanup at {}",
                record.evidence,
                callers.join(", ")
            ),
        ))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::Confidence;

    /// The convention record inside the union, for asserting against.
    fn convention(inference: &InferredType) -> &InferredConvention {
        match inference {
            InferredType::Convention(record) => record,
            other => panic!("expected a convention record, got {other:?}"),
        }
    }

    /// A per-function convention reading, as the scan's resolution
    /// hands it to the pass.
    fn reading(
        function: &str,
        convention: CallingConvention,
        method: InferenceMethod,
        confidence: u8,
        evidence: &str,
    ) -> InferredType {
        convention_record(function, convention, method, confidence, evidence)
    }

    /// An epilogue reading for a decorated function: `paint@12` with a
    /// `ret 0xC` — the decoration and the epilogue already agree.
    fn epilogue_reading(function: &str) -> InferredType {
        reading(
            function,
            CallingConvention::Stdcall,
            InferenceMethod::CalleeEpilogue,
            80,
            "00401007  RET 0xC",
        )
    }

    /// A canned esp-spelled caller calling `callee` with no cleanup
    /// after the call.
    fn clean_caller_listing(callee: &str) -> String {
        format!(
            "00401100  PUSH EBP\n\
             00401103  CALL {callee}\n\
             00401108  POP EBP\n\
             0040110c  RET"
        )
    }

    /// A canned esp-spelled caller popping after the call — the
    /// contradiction of a callee-pops convention.
    fn cleaning_caller_listing(callee: &str) -> String {
        format!(
            "00401100  PUSH EBP\n\
             00401103  CALL {callee}\n\
             00401108  ADD ESP, 0x8\n\
             0040110c  RET"
        )
    }

    #[test]
    fn a_detector_carries_no_state() {
        let detector = ConventionCorroborator::new();
        assert_eq!(detector, ConventionCorroborator);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConventionCorroborator>();
    }

    // ---- the callee-pops family ----

    #[test]
    fn epilogue_clean_sites_and_declared_bytes_bump_above_the_per_function_tier() {
        // `paint@12` pops 0xC itself, its one caller pops nothing, and
        // the decoration declares the same 12 bytes: three spellings
        // across functions agree, so the reading lands above every
        // single one.
        let readings = vec![epilogue_reading("paint@12")];
        let caller = clean_caller_listing("paint@12");
        let listings = [
            ("paint@12", "00401000  MOV EBP, ESP\n00401007  RET 0xC"),
            ("FUN_18003ab00", caller.as_str()),
        ];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        let record = convention(&records[0]);
        assert_eq!(record.function, "paint@12");
        assert_eq!(record.callee, None);
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::CorroboratedConvention);
        assert_eq!(record.confidence, Confidence::new(92));
        assert_eq!(
            record.evidence,
            "00401007  RET 0xC; no caller cleanup at FUN_18003ab00; declared bytes @12 agrees"
        );
    }

    #[test]
    fn a_clean_site_alone_never_bumps_the_epilogue() {
        // No `@N` decoration to agree with: the epilogue keeps its own
        // band, and the pass still lands the call-site record.
        let readings = vec![epilogue_reading("FUN_18003e750")];
        let caller = clean_caller_listing("FUN_18003e750");
        let listings = [
            ("FUN_18003e750", "00401000  MOV EBP, ESP\n00401007  RET 0xC"),
            ("FUN_18003ab00", caller.as_str()),
        ];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert_eq!(records.len(), 1, "only the call-site record lands");
        assert_eq!(
            convention(&records[0]).method,
            InferenceMethod::CallSiteConvention
        );
    }

    #[test]
    fn a_mismatched_decoration_never_bumps_the_epilogue() {
        // `paint@16` declares sixteen bytes but its epilogue pops
        // twelve: the spellings disagree, so nothing is corroborated.
        let readings = vec![epilogue_reading("paint@16")];
        let caller = clean_caller_listing("paint@16");
        let listings = [("FUN_18003ab00", caller.as_str())];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert!(
            records
                .iter()
                .all(|record| convention(record).method != InferenceMethod::CorroboratedConvention),
            "disagreement corroborates nothing"
        );
    }

    #[test]
    fn one_cleaning_caller_contradicts_the_whole_family() {
        // Two callers, one pops after the call: the readings disagree
        // across functions, and the pass bumps nothing — resolution
        // leaves the higher-confidence single reading standing.
        let readings = vec![epilogue_reading("paint@12")];
        let clean = clean_caller_listing("paint@12");
        let cleaning = cleaning_caller_listing("paint@12");
        let listings = [
            ("FUN_18003ab00", clean.as_str()),
            ("FUN_1800412a0", cleaning.as_str()),
        ];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert!(
            records
                .iter()
                .all(|record| convention(record).method != InferenceMethod::CorroboratedConvention),
            "a caller that pops contradicts the callee-pops family"
        );
    }

    #[test]
    fn a_callee_with_no_caller_sites_never_bumps() {
        // Agreement needs another function's word: an epilogue read in
        // a function no kept listing calls stands at its own band.
        let readings = vec![epilogue_reading("paint@12")];
        let listings = [("paint@12", "00401007  RET 0xC")];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert!(records.is_empty());
    }

    // ---- the x64 family ----

    #[test]
    fn x64_shape_with_clean_64_bit_sites_bumps_above_the_shape_tier() {
        // The callee's shape reading plus a call site in an
        // rsp-spelled caller that pops nothing: the discipline holds
        // across the boundary, so the reading climbs above its
        // shape-only tier — but stays below every exact spelling.
        let readings = vec![reading(
            "FUN_18003e750",
            CallingConvention::MicrosoftX64,
            InferenceMethod::X64Shape,
            65,
            "140001000  SUB RSP, 0x28",
        )];
        let caller = "140002000  SUB RSP, 0x28\n\
                      140002007  MOV [RSP+0x8], RCX\n\
                      14000200c  CALL FUN_18003e750\n\
                      140002011  ADD RSP, 0x28\n\
                      140002015  RET";
        let listings = [("FUN_18003ab00", caller)];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        let record = convention(&records[0]);
        assert_eq!(record.convention, CallingConvention::MicrosoftX64);
        assert_eq!(record.method, InferenceMethod::CorroboratedConvention);
        assert_eq!(record.confidence, Confidence::new(75));
        assert_eq!(
            record.evidence,
            "140001000  SUB RSP, 0x28; no caller cleanup at FUN_18003ab00"
        );
    }

    #[test]
    fn an_esp_spelled_caller_contradicts_the_x64_family() {
        // A 32-bit-spelled caller means the two families crossed: the
        // x64 reading is not corroborated, and the families'
        // non-cross-firing rule stands on the caller side too.
        let readings = vec![reading(
            "FUN_18003e750",
            CallingConvention::MicrosoftX64,
            InferenceMethod::X64Shape,
            65,
            "140001000  SUB RSP, 0x28",
        )];
        let caller = clean_caller_listing("FUN_18003e750");
        let listings = [("FUN_18003ab00", caller.as_str())];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert!(
            records
                .iter()
                .all(|record| convention(record).method != InferenceMethod::CorroboratedConvention),
            "an esp-spelled caller never corroborates an x64 reading"
        );
    }

    // ---- the call-site records ----

    #[test]
    fn a_detected_convention_lands_a_record_at_each_caller_s_site() {
        // The callee's stdcall reading projects into both callers:
        // each record is keyed by the caller, names the callee, and
        // carries the callee's own convention and confidence.
        let readings = vec![reading(
            "FUN_1800412a0",
            CallingConvention::Stdcall,
            InferenceMethod::CalleeEpilogue,
            80,
            "00401007  RET 0xC",
        )];
        let first = clean_caller_listing("FUN_1800412a0");
        let second = clean_caller_listing("FUN_1800412a0");
        let listings = [
            ("FUN_18003ab00", first.as_str()),
            ("FUN_180041f00", second.as_str()),
        ];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert_eq!(records.len(), 2);
        for (caller, record) in [
            ("FUN_18003ab00", convention(&records[0])),
            ("FUN_180041f00", convention(&records[1])),
        ] {
            assert_eq!(record.function, caller);
            assert_eq!(record.callee.as_deref(), Some("FUN_1800412a0"));
            assert_eq!(record.convention, CallingConvention::Stdcall);
            assert_eq!(record.method, InferenceMethod::CallSiteConvention);
            assert_eq!(record.confidence, Confidence::new(80));
            assert_eq!(record.evidence, "00401103  CALL FUN_1800412a0");
        }
    }

    #[test]
    fn a_bumped_callee_s_call_sites_carry_the_bumped_reading() {
        // The caller's view matches the callee's *surviving* record:
        // once the family corroborates, the sites carry the bumped
        // convention and confidence too.
        let readings = vec![epilogue_reading("paint@12")];
        let caller = clean_caller_listing("paint@12");
        let listings = [("FUN_18003ab00", caller.as_str())];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert_eq!(records.len(), 2, "the bump and the site record");
        let site = convention(&records[1]);
        assert_eq!(site.callee.as_deref(), Some("paint@12"));
        assert_eq!(site.confidence, Confidence::new(92));
    }

    #[test]
    fn name_borne_readings_land_call_site_records_too() {
        // A mangled letter's reading is a detected convention like any
        // other: its call sites get the same view.
        let readings = vec![reading(
            "?paint@Widget@@QAEXXZ",
            CallingConvention::Thiscall,
            InferenceMethod::MangledConvention,
            90,
            "?paint@Widget@@QAEXXZ",
        )];
        let listing = "00401100  PUSH EBP\n\
                       00401103  CALL ?paint@Widget@@QAEXXZ\n\
                       00401108  RET";
        let listings = [("FUN_18003ab00", listing)];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert_eq!(records.len(), 1);
        let record = convention(&records[0]);
        assert_eq!(record.callee.as_deref(), Some("?paint@Widget@@QAEXXZ"));
        assert_eq!(record.convention, CallingConvention::Thiscall);
        assert_eq!(record.confidence, Confidence::new(90));
    }

    #[test]
    fn address_and_indirect_call_sites_name_no_callee_and_land_nothing() {
        // The engine's own rows call through an address; an indirect
        // call runs through a register. Neither names the detected
        // callee, so no view lands.
        let readings = vec![reading(
            "FUN_1800412a0",
            CallingConvention::Stdcall,
            InferenceMethod::CalleeEpilogue,
            80,
            "00401007  RET 0xC",
        )];
        let listing = "00401100  PUSH EBP\n\
                       00401103  CALL 0x401100\n\
                       00401108  CALL EAX\n\
                       0040110c  RET";
        let listings = [("FUN_18003ab00", listing)];
        let records = ConventionCorroborator::new().corroborate(&readings, &listings);

        assert!(records.is_empty());
    }

    #[test]
    fn records_append_in_listing_order() {
        // Two scans of one program diff cleanly: bumps first in
        // reading order, then site records caller by caller, site by
        // site.
        let readings = vec![
            reading(
                "FUN_1800412a0",
                CallingConvention::Stdcall,
                InferenceMethod::CalleeEpilogue,
                80,
                "00401007  RET 0xC",
            ),
            reading(
                "FUN_180041f00",
                CallingConvention::Stdcall,
                InferenceMethod::CalleeEpilogue,
                80,
                "00401007  RET 0x4",
            ),
        ];
        let first = clean_caller_listing("FUN_1800412a0");
        let second = "00401200  CALL FUN_1800412a0\n00401205  NOP\n00401206  CALL FUN_1800412a0";
        let listings = [("FUN_18003ab00", first.as_str()), ("FUN_18003e750", second)];
        let pass = ConventionCorroborator::new();
        let one = pass.corroborate(&readings, &listings);
        let two = pass.corroborate(&readings, &listings);
        assert_eq!(one, two, "the pass is deterministic");

        let views: Vec<(&str, &str)> = one
            .iter()
            .map(|record| {
                let record = convention(record);
                (record.function.as_str(), record.callee.as_deref().unwrap())
            })
            .collect();
        assert_eq!(
            views,
            [
                ("FUN_18003ab00", "FUN_1800412a0"),
                ("FUN_18003e750", "FUN_1800412a0"),
            ],
            "one view per caller and callee, following listing order, evidenced by the first site"
        );
        assert_eq!(
            convention(&one[1]).evidence,
            "00401200  CALL FUN_1800412a0",
            "the first site naming the callee carries the view"
        );
    }

    #[test]
    fn call_site_views_never_seed_the_pass() {
        // A caller's view of its callee is not the callee's own
        // reading: it neither bumps nor projects further.
        let view = InferredType::Convention(InferredConvention {
            function: "FUN_18003ab00".into(),
            callee: Some("FUN_1800412a0".into()),
            convention: CallingConvention::Stdcall,
            method: InferenceMethod::CallSiteConvention,
            confidence: Confidence::new(80),
            evidence: "00401103  CALL FUN_1800412a0".into(),
        });
        let caller = clean_caller_listing("FUN_1800412a0");
        let listings = [("FUN_18003ab00", caller.as_str())];
        let records = ConventionCorroborator::new().corroborate(&[view], &listings);

        assert!(records.is_empty());
    }

    #[test]
    fn corroboration_over_a_program_sized_listing_set_stays_program_speed() {
        // The 2026-10-20 LaunchPad.exe incident: a stripped 32-bit
        // image listed 7,267 functions, nearly every one carrying a
        // `ret N` epilogue reading. The pass probed every reading
        // against every listing, re-splitting and re-parsing each
        // listing per probe — billions of row parses, tens of minutes
        // at 100% CPU, the scan looked hung. The pass reads each
        // listing once now, so a program-sized input finishes in
        // program time; the bound is generous (the fixed pass runs in
        // hundredths of a second here, the quadratic one took minutes).
        const FUNCTIONS: usize = 2_000;
        const PAD_ROWS: usize = 200;
        let names: Vec<String> = (0..FUNCTIONS).map(|i| format!("sub_{i:06x}")).collect();
        let listings: Vec<(String, String)> = (0..FUNCTIONS)
            .map(|i| {
                let mut text = String::new();
                for pad in 0..PAD_ROWS {
                    text.push_str(&format!("00401000  MOV EAX, ECX ; pad {pad}\n"));
                }
                for hop in 1..=5u64 {
                    let callee = &names[(i + (hop as usize) * FUNCTIONS / 6) % FUNCTIONS];
                    text.push_str(&format!("00402000  CALL {callee}\n"));
                }
                text.push_str("00403000  RET 0x8\n");
                (names[i].clone(), text)
            })
            .collect();
        let readings: Vec<InferredType> = names
            .iter()
            .map(|name| {
                reading(
                    name,
                    CallingConvention::Stdcall,
                    InferenceMethod::CalleeEpilogue,
                    80,
                    "00403000  RET 0x8",
                )
            })
            .collect();
        let kept: Vec<(&str, &str)> = listings
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();

        let started = std::time::Instant::now();
        let records = ConventionCorroborator::new().corroborate(&readings, &kept);
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "corroboration of {FUNCTIONS} functions took {elapsed:?} — the pass went quadratic again"
        );

        // Still correct at scale: no bumps (the undecorated names carry
        // no `@N` to agree with) and exactly one call-site view per
        // (caller, callee) pair — five callees per caller, none naming
        // itself — in listing order, callee by record order.
        assert_eq!(records.len(), FUNCTIONS * 5);
        let first = convention(&records[0]);
        assert_eq!(first.function, "sub_000000");
        assert_eq!(first.callee.as_deref(), Some(names[FUNCTIONS / 6].as_str()));
        assert_eq!(first.method, InferenceMethod::CallSiteConvention);
        assert_eq!(first.evidence, "00402000  CALL sub_00014d");
    }
}
