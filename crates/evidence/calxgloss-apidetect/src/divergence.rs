//! Platform-divergence detection over the classified import listing.
//!
//! A binary that imports both Win32 file APIs and POSIX/C-runtime
//! stdio APIs uses two platform families at once. A translation that
//! transliterates both families as unconditional calls compiles on
//! neither platform. [`detect_divergence`] reads this portability fact
//! from the classified import findings the
//! [`ImportTableScanner`](crate::import_table) already emitted — no new
//! [`ScanSource`](crate::engine::ScanSource) reads — and records at
//! most one binary-level [`PlatformDivergence`] claim per scan. The
//! claim names both families and lists the triggering imports from
//! both sides as evidence.
//!
//! The honesty gate is the point of the module: the claim needs *both*
//! families — at least one import whose mapping category names the
//! Win32 family (`Win32Core`) **and** at least one naming the POSIX
//! family (`POSIX`, or its C-runtime surface, `stdio`). A purely Win32
//! or purely POSIX binary claims nothing. Unidentified and
//! ordinal-only imports have no category and join neither side. The
//! platform-neutral categories (DirectX, SDL2, PNG, zlib, C++ STL)
//! count on neither side. Only the import entries count — a usage
//! finding repeats an import the listing already has. Custom mappings
//! join the gate by naming one of the gate's categories with their
//! [`category`](crate::lib_mapping::LibraryMapping::category).

use crate::types::{ApiFinding, Confidence, PlatformDivergence};

/// Confidence of a divergence reading. Each triggering import is an
/// identified entry at confidence 90, but the portability claim over
/// their pairing is an inference. It sits at 70, level with the other
/// structural readings.
pub const DIVERGENCE_CONFIDENCE: u8 = 70;

/// The Rust shape a divergence finding suggests: the platform-specific
/// calls gated per family, not both families transliterated
/// unconditionally.
pub const DIVERGENCE_SUGGESTION: &str = "translate the platform-specific calls behind cfg gates — the Win32 family under `#[cfg(windows)]`, the POSIX/stdio family under `#[cfg(unix)]` — not both families unconditionally";

/// The mapping categories whose imports count on the Win32 side of the
/// gate, spelled with the PAL `ApiCategory` display names.
const WIN32_CATEGORIES: &[&str] = &["Win32Core"];

/// The mapping categories whose imports count on the POSIX side of the
/// gate — the POSIX family and its C-runtime stdio surface.
const POSIX_CATEGORIES: &[&str] = &["POSIX", "stdio"];

/// Find the platform families in the classified import findings.
///
/// Returns exactly one [`ApiFinding::PlatformDivergence`] when the
/// listing has both a Win32-category and a POSIX/stdio-category
/// import. However many imports sit on either side, the cap is one
/// claim per binary; otherwise this returns `None`. The claim's
/// families are the categories that triggered it, Win32 side first.
/// Its evidence lists the triggering imports from both sides, each
/// spelled `api (category)`, each side in import-listing order.
pub fn detect_divergence(findings: &[ApiFinding]) -> Option<ApiFinding> {
    let mut win32_categories: Vec<String> = Vec::new();
    let mut posix_categories: Vec<String> = Vec::new();
    let mut win32_imports: Vec<String> = Vec::new();
    let mut posix_imports: Vec<String> = Vec::new();

    for finding in findings {
        let ApiFinding::Import(record) = finding else {
            continue;
        };
        let Some(category) = record.category.as_deref() else {
            continue;
        };
        if WIN32_CATEGORIES.contains(&category) {
            if !win32_categories.iter().any(|seen| seen == category) {
                win32_categories.push(category.to_string());
            }
            win32_imports.push(format!("{} ({category})", record.api));
        } else if POSIX_CATEGORIES.contains(&category) {
            if !posix_categories.iter().any(|seen| seen == category) {
                posix_categories.push(category.to_string());
            }
            posix_imports.push(format!("{} ({category})", record.api));
        }
    }

    if win32_imports.is_empty() || posix_imports.is_empty() {
        return None;
    }

    Some(ApiFinding::PlatformDivergence(PlatformDivergence {
        families: [win32_categories, posix_categories].concat(),
        evidence: win32_imports
            .iter()
            .chain(&posix_imports)
            .cloned()
            .collect::<Vec<String>>()
            .join(", "),
        confidence: Confidence::new(DIVERGENCE_CONFIDENCE),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApiSignature, ApiUsage};

    fn import(api: &str, category: Option<&str>) -> ApiFinding {
        ApiFinding::Import(ApiSignature {
            api: api.into(),
            library: category.map(|_| "SomeLibrary".into()),
            rust_crate: category.map(|_| "some_crate".into()),
            category: category.map(str::to_string),
            features: Vec::new(),
            confidence: Confidence::new(if category.is_some() { 90 } else { 0 }),
        })
    }

    fn usage(api: &str, category: &str) -> ApiFinding {
        ApiFinding::ApiUsage(ApiUsage {
            function: "FUN_18003ab00".into(),
            api: api.into(),
            library: "SomeLibrary".into(),
            rust_crate: "some_crate".into(),
            category: Some(category.into()),
            features: Vec::new(),
            direct: true,
            confidence: Confidence::new(80),
            evidence: format!("FUN_18003ab00 → {api}"),
        })
    }

    #[test]
    fn the_mixed_listing_claims_exactly_one_divergence_finding() {
        // Many imports on both sides still produce one claim per
        // binary — the Option return is itself the cap.
        let listing = [
            import("CreateFileA", Some("Win32Core")),
            import("GetLastError", Some("Win32Core")),
            import("fopen", Some("POSIX")),
            import("printf", Some("POSIX")),
            import("puts", Some("stdio")),
        ];
        let finding = detect_divergence(&listing).expect("both families appear");
        assert_eq!(finding.kind(), "platform_divergence");
        assert_eq!(
            finding.target(),
            "Win32Core + POSIX + stdio",
            "every triggering category is named, Win32 side first"
        );
    }

    #[test]
    fn a_purely_win32_listing_claims_nothing() {
        let listing = [
            import("CreateFileA", Some("Win32Core")),
            import("GetLastError", Some("Win32Core")),
        ];
        assert!(
            detect_divergence(&listing).is_none(),
            "a purely Win32 binary is not over-read"
        );
    }

    #[test]
    fn a_purely_posix_listing_claims_nothing() {
        let listing = [
            import("fopen", Some("POSIX")),
            import("puts", Some("stdio")),
        ];
        assert!(
            detect_divergence(&listing).is_none(),
            "a purely POSIX binary is not over-read"
        );
    }

    #[test]
    fn stdio_alone_opens_the_posix_side_of_the_gate() {
        let listing = [
            import("CreateFileA", Some("Win32Core")),
            import("puts", Some("stdio")),
        ];
        let finding = detect_divergence(&listing).expect("stdio counts as the POSIX side");
        assert_eq!(finding.target(), "Win32Core + stdio");
    }

    #[test]
    fn unidentified_and_platform_neutral_imports_join_neither_side() {
        let with_unidentified = [
            import("CreateFileA", Some("Win32Core")),
            import("VendorSpecialFunction", None),
        ];
        assert_eq!(
            detect_divergence(&with_unidentified),
            None,
            "a category-less import claims no family"
        );

        let platform_neutral = [
            import("CreateFileA", Some("Win32Core")),
            import("inflate", Some("zlib")),
            import("Direct3DCreate9", Some("DirectX")),
        ];
        assert_eq!(
            detect_divergence(&platform_neutral),
            None,
            "zlib and DirectX are not a platform family"
        );

        let posix_with_neutral = [
            import("fopen", Some("POSIX")),
            import("inflate", Some("zlib")),
        ];
        assert_eq!(detect_divergence(&posix_with_neutral), None);
    }

    #[test]
    fn only_import_entries_stand_on_the_gate() {
        // A usage finding repeats an import the listing already has;
        // the gate reads the import entries, not the usages.
        let listing = [
            usage("CreateFileA", "Win32Core"),
            import("fopen", Some("POSIX")),
        ];
        assert_eq!(detect_divergence(&listing), None);
    }

    #[test]
    fn the_evidence_names_the_triggering_imports_from_both_sides() {
        let listing = [
            import("fopen", Some("POSIX")),
            import("CreateFileA", Some("Win32Core")),
            import("puts", Some("stdio")),
            import("GetLastError", Some("Win32Core")),
        ];
        let finding = detect_divergence(&listing).expect("both families appear");
        assert_eq!(
            finding.evidence(),
            // Win32 side first, each side in listing order.
            "CreateFileA (Win32Core), GetLastError (Win32Core), fopen (POSIX), puts (stdio)"
        );
    }

    #[test]
    fn the_finding_is_binary_level_at_a_fixed_confidence() {
        let listing = [
            import("CreateFileA", Some("Win32Core")),
            import("malloc", Some("POSIX")),
        ];
        let finding = detect_divergence(&listing).expect("both families appear");
        assert_eq!(finding.function(), "", "the claim belongs to the binary");
        assert_eq!(finding.confidence(), Confidence::new(DIVERGENCE_CONFIDENCE));
        assert_eq!(finding.kind(), "platform_divergence");
    }

    #[test]
    fn the_suggestion_names_cfg_gated_translation() {
        let listing = [
            import("CreateFileA", Some("Win32Core")),
            import("malloc", Some("POSIX")),
        ];
        let finding = detect_divergence(&listing).expect("both families appear");
        let suggestion = finding.suggestion();
        assert!(suggestion.contains("cfg gates"), "got: {suggestion}");
        assert!(suggestion.contains("#[cfg(windows)]"), "got: {suggestion}");
        assert!(suggestion.contains("#[cfg(unix)]"), "got: {suggestion}");
    }

    #[test]
    fn the_detector_state_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PlatformDivergence>();
        assert_send_sync::<ApiFinding>();
    }
}
