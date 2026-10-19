//! Calling-convention detection: the convention a name already spells.
//!
//! Two name-borne channels tell how a function is called without reading
//! a single instruction:
//!
//! - **the convention letter of an MSVC-mangled listing symbol** — the
//!   property letters carry it (`A` cdecl, `C`/`E`/`G` thiscall, `I`
//!   stdcall), and the mangling decoder already reads the letter for
//!   parseability and used to throw it away;
//! - **the `@N` decoration on an import name** — `CreateFileA@28` declares
//!   twenty-eight argument bytes, and only a callee-pops convention can
//!   leave a fixed byte count to name, so the decoration spells stdcall.
//!
//! Each reading lands as a [`InferredType::Convention`] record keyed by
//! the name as spelled, with the name itself as evidence — one record per
//! function, the same keying the return record uses. The two channels
//! carry their own method variants ([`InferenceMethod::MangledConvention`]
//! and [`InferenceMethod::ImportDecoration`]) and their own confidence
//! bands: both are near-certain spellings, the letter scoring at
//! [`MANGLED_LETTER_CONFIDENCE`] and the decoration at
//! [`IMPORT_DECORATION_CONFIDENCE`]; nothing self-upgrades.
//!
//! A name that spells no convention in the closed set produces nothing:
//! an undecorated import, a Pascal-spelled `B` letter — outside the set —
//! and the namespace-noise guard the mangling detector applies to `std::`
//! and `operator` members all yield no reading rather than a guess. The
//! body-evidence channels (epilogue `ret N`, caller stack cleanup, x64
//! shape) read the conventions no name spells; they are separate passes
//! over the disassembly, in [`crate::stack_discipline`].

use crate::mangling::{is_namespace_noise, parse_msvc};
use crate::types::{CallingConvention, InferenceMethod, InferredConvention, InferredType};

/// Confidence of the reading an MSVC-mangled name's convention letter
/// carries: the symbol states the convention outright, so it sits at the
/// top of the scale beside the structural dispatch evidence — above the
/// name's own type contract (mangling 80), which the same symbol also
/// carries.
const MANGLED_LETTER_CONFIDENCE: u8 = 90;

/// Confidence of the reading an `@N` import decoration carries: the byte
/// count is stated exactly, but it names the import's decoration rather
/// than the symbol's own encoding, so it sits a notch below the mangled
/// letter and beside the vtable/COM dispatch band.
const IMPORT_DECORATION_CONFIDENCE: u8 = 85;

/// Assemble one convention reading into its record: the channel's method
/// and confidence, the function keyed by the name or listing evidence,
/// and the evidence text itself. Shared by the name-borne channels
/// below and by the listing-borne channels of [`crate::stack_discipline`].
pub(crate) fn convention_record(
    function: &str,
    convention: CallingConvention,
    method: InferenceMethod,
    confidence: u8,
    evidence: &str,
) -> InferredType {
    InferredType::Convention(InferredConvention {
        function: function.to_string(),
        callee: None,
        convention,
        method,
        confidence: confidence.into(),
        evidence: evidence.to_string(),
    })
}

/// The declared argument bytes an `@N` import decoration spells, when the
/// name carries one: a non-empty base name, then `@`, then a non-empty
/// run of digits. `CreateFileA@28` spells 28; a plain `CloseHandle`, an
/// ordinal placeholder, and a mangled name's trailing `@Z` spell nothing
/// — the digit guard is what keeps decorated imports apart from the
/// `@`-separated segments of a mangled symbol. Shared with the
/// cross-function corroboration pass of [`crate::corroboration`].
pub(crate) fn declared_argument_bytes(name: &str) -> Option<&str> {
    let (base, digits) = name.rsplit_once('@')?;
    (!base.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .then_some(digits)
}

// ============================================================
// Detector
// ============================================================

/// Calling-convention analysis over listing and import names.
///
/// The detector is stateless: every reading comes from the name it is
/// handed, so one detector serves an entire scan. It fetches nothing
/// itself — the engine hands it the listing names and the import names,
/// the same names the mangling detector reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConventionDetector;

impl ConventionDetector {
    /// A detector with the full name-borne reading set.
    pub fn new() -> Self {
        Self
    }

    /// The convention reading an MSVC-mangled listing symbol carries,
    /// keyed by the symbol verbatim with the symbol itself as evidence.
    ///
    /// The reading comes from the same decode the mangling detector runs
    /// for parameter types — the convention letter is part of the
    /// symbol's property letters — and the same guards apply: a name that
    /// is not mangled, or whose encoding falls outside the practical
    /// subset, produces nothing, and a `std::` or `operator` member names
    /// library plumbing rather than a function of the analyzed program.
    /// A letter outside the closed set (a Pascal-spelled `B`) decodes for
    /// types but spells no convention.
    pub fn from_listing_name(&self, name: &str) -> Option<InferredType> {
        let signature = parse_msvc(name)?;
        if is_namespace_noise(signature.class.as_deref()) {
            return None;
        }
        let convention = signature.convention?;
        Some(convention_record(
            name,
            convention,
            InferenceMethod::MangledConvention,
            MANGLED_LETTER_CONFIDENCE,
            name,
        ))
    }

    /// The convention reading an import name's `@N` decoration carries,
    /// keyed by the name as spelled with the name itself as evidence:
    /// the declared argument byte count means the callee pops its own
    /// arguments, so the import is called stdcall.
    ///
    /// An undecorated import — a plain `CloseHandle` — spells nothing
    /// here; its convention comes from the body-evidence channels. A
    /// mangled name's trailing `@Z` is not a decoration: only a run of
    /// digits after the last `@` counts.
    pub fn from_import_name(&self, name: &str) -> Option<InferredType> {
        declared_argument_bytes(name)?;
        Some(convention_record(
            name,
            CallingConvention::Stdcall,
            InferenceMethod::ImportDecoration,
            IMPORT_DECORATION_CONFIDENCE,
            name,
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

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = ConventionDetector::new();
        assert_eq!(detector, ConventionDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven concurrently over a program's listing,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConventionDetector>();
    }

    // ---- the mangled convention letter ----

    #[test]
    fn a_mangled_member_letter_reads_thiscall_beside_the_this_pointer() {
        // `void Widget::paint(void)`: the `E` in `QAE` is the member's
        // thiscall letter — the same symbol whose implicit `this` the
        // mangling detector types, so the member reads as a method.
        let reading = ConventionDetector::new()
            .from_listing_name("?paint@Widget@@QAEXXZ")
            .expect("the letter spells a convention");
        let record = convention(&reading);
        assert_eq!(record.function, "?paint@Widget@@QAEXXZ");
        assert_eq!(record.convention, CallingConvention::Thiscall);
        assert_eq!(record.method, InferenceMethod::MangledConvention);
        assert_eq!(
            record.confidence,
            Confidence::new(MANGLED_LETTER_CONFIDENCE)
        );
        assert_eq!(record.evidence, "?paint@Widget@@QAEXXZ");
    }

    #[test]
    fn the_member_letters_all_spell_thiscall() {
        // `C`, `E`, and `G` are the member thiscall spellings (`G` the
        // old EVC one); each yields the same convention.
        let detector = ConventionDetector::new();
        for name in [
            "?a@Widget@@QACXXZ",
            "?paint@Widget@@QAEXXZ",
            "?old@Widget@@QAGXXZ",
        ] {
            let reading = detector
                .from_listing_name(name)
                .expect("the letter spells a convention");
            assert_eq!(
                convention(&reading).convention,
                CallingConvention::Thiscall,
                "{name}"
            );
        }
    }

    #[test]
    fn a_free_cdecl_letter_reads_cdecl() {
        // `int compare(int, int)` as a free cdecl function: the `A` after
        // the free-function `Y` is the cdecl letter.
        let reading = ConventionDetector::new()
            .from_listing_name("?compare@@YAHHI@Z")
            .expect("the letter spells a convention");
        assert_eq!(convention(&reading).convention, CallingConvention::Cdecl);
    }

    #[test]
    fn a_mangled_stdcall_letter_reads_stdcall() {
        // A free `__stdcall` function: the `I` after `Y` is the stdcall
        // letter.
        let reading = ConventionDetector::new()
            .from_listing_name("?add@@YIHH@Z")
            .expect("the letter spells a convention");
        assert_eq!(convention(&reading).convention, CallingConvention::Stdcall);
    }

    #[test]
    fn a_pascal_letter_carries_no_convention_reading() {
        // `B` spells Pascal — outside the closed set. The name still
        // decodes for types (the mangling detector reads it), but this
        // channel yields no convention rather than a near-miss.
        assert!(
            ConventionDetector::new()
                .from_listing_name("?add@@YBHH@Z")
                .is_none()
        );
    }

    #[test]
    fn an_unmangled_or_unparseable_name_carries_no_reading() {
        // The same guards the mangling detector applies: an ordinary
        // symbol, and a mangled name outside the practical subset.
        let detector = ConventionDetector::new();
        assert!(detector.from_listing_name("GetLastError").is_none());
        assert!(
            detector
                .from_listing_name("?cb@Widget@@QAEP6GXZ@Z")
                .is_none()
        );
    }

    #[test]
    fn a_std_namespace_member_carries_no_reading() {
        // The mangling detector's namespace-noise guard applies here too:
        // a mangled `std::` member names library plumbing, and its
        // convention is not a reading about the analyzed program.
        assert!(
            ConventionDetector::new()
                .from_listing_name("?compare@string@std@@QBEPBH@Z")
                .is_none()
        );
    }

    // ---- the `@N` import decoration ----

    #[test]
    fn a_decorated_import_reads_stdcall() {
        // `CreateFileA@28` declares twenty-eight argument bytes: only a
        // callee-pops convention can spell a fixed byte count.
        let reading = ConventionDetector::new()
            .from_import_name("CreateFileA@28")
            .expect("the decoration spells a convention");
        let record = convention(&reading);
        assert_eq!(record.function, "CreateFileA@28");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::ImportDecoration);
        assert_eq!(
            record.confidence,
            Confidence::new(IMPORT_DECORATION_CONFIDENCE)
        );
        assert_eq!(record.evidence, "CreateFileA@28");
    }

    #[test]
    fn an_undecorated_import_carries_no_reading() {
        // A plain `CloseHandle` import spells nothing: its convention
        // comes from the body-evidence channels, not a guess.
        assert!(
            ConventionDetector::new()
                .from_import_name("CloseHandle")
                .is_none()
        );
    }

    #[test]
    fn only_a_digit_count_after_the_last_at_is_a_decoration() {
        // The digit guard keeps mangled `@` segments and ordinal
        // placeholders out: `@Z` ends a mangled name, `Ordinal_123` has
        // no `@` at all, and empty or mixed spellings name no byte count.
        let detector = ConventionDetector::new();
        assert!(
            detector
                .from_import_name("?copy@Widget@@QAGPADPAD@Z")
                .is_none()
        );
        assert!(detector.from_import_name("Ordinal_123").is_none());
        assert!(detector.from_import_name("CreateFileA@").is_none());
        assert!(detector.from_import_name("CreateFileA@2a").is_none());
        assert!(detector.from_import_name("@28").is_none());
    }
}
