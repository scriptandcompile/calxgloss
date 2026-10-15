//! Localization signal detection.
//!
//! A binary's language machinery leaves a distinctive shape in the strings
//! a function uses: a whole string that is a language name (`"English"`,
//! `"French"` — the arms of a language-selection ladder), a locale code
//! (`en-US`, `fr_FR`), or user-facing text carrying non-ASCII characters
//! (accented Latin, CJK). [`LocalizationDetector`] reads those three
//! signal kinds off the string values the scan already maps to each
//! function and reports them as one [`LocalizationSignals`] record per
//! function — a structural reading that rides beside the classified
//! records and never reclassifies them.
//!
//! The honesty gates are the point of the module:
//!
//! - A language word buried inside a longer sentence — `"Do you speak
//!   English?"` — claims nothing; only the *whole* string value being a
//!   language name is a signal.
//! - The non-ASCII signal reads only values the decoded program string
//!   listing carries, so an escaped body literal (`"caf\xe9"` as the
//!   decompiler writes it) can neither fake a signal the program does not
//!   hold nor hide one the listing has decoded, and only the classifier's
//!   user-facing buckets (`UserVisible`/`Error`) claim it — internal
//!   identifiers and data blobs with high bytes say nothing about
//!   localization.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{Confidence, LocalizationSignalKind, LocalizationSignals, StringClassification};

/// Confidence for a localization reading: a pattern inference over string
/// shapes, visibly below the 70 a directly classified record carries.
pub const LOCALIZATION_CONFIDENCE: u8 = 60;

/// The Rust shape every localization finding suggests: the language
/// switch as an enum with the localized strings held in a table, in place
/// of the string ladder the decompiled body shows.
pub const LOCALIZATION_SUGGESTION: &str =
    "model the language switch as a Rust enum with the localized strings held in a table";

/// The language names the default detector claims, stored lowercase so
/// the whole-string match is case-insensitive. A binary's own spellings
/// are reachable through [`LocalizationDetector::with_names`].
pub const DEFAULT_LANGUAGE_NAMES: &[&str] = &[
    "arabic",
    "chinese",
    "croatian",
    "czech",
    "danish",
    "dutch",
    "english",
    "finnish",
    "french",
    "german",
    "greek",
    "hebrew",
    "hindi",
    "hungarian",
    "italian",
    "japanese",
    "korean",
    "norwegian",
    "polish",
    "portuguese",
    "romanian",
    "russian",
    "slovak",
    "spanish",
    "swedish",
    "thai",
    "turkish",
    "ukrainian",
    "vietnamese",
];

/// The `xx-YY`/`xx_YY` locale shape: two lowercase letters, the separator,
/// two uppercase letters — `en-US`, `fr_FR`. A longer or differently
/// cased value (`en-USA`, `EN-US`) is not the shape.
fn locale_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z]{2}[-_][A-Z]{2}$").expect("static pattern"))
}

/// One string the scan mapped to a function, as the localization detector
/// reads it: the value, the classification the scan gave it, whether the
/// value is one of the decoded program string listing's values, and the
/// line that shows the use.
#[derive(Debug, Clone)]
pub(crate) struct MappedStringSignal<'a> {
    /// The string's contents, as the scan recorded them.
    pub value: &'a str,
    /// The category the classifier read the string as.
    pub classification: StringClassification,
    /// Whether the value is a decoded value from the program string
    /// listing — the only values the non-ASCII signal may read.
    pub from_listing: bool,
    /// The decompiled line or xref that shows the use.
    pub evidence: &'a str,
}

/// Reads the three localization signal kinds off one function's mapped
/// strings and reports them as one [`LocalizationSignals`] record.
///
/// The detector holds no per-scan state beyond the language-name set, so
/// one instance serves a whole scan; [`with_names`](Self::with_names)
/// swaps the set whole, mirroring the classifier's and mapper's
/// configured-name conventions.
#[derive(Debug, Clone)]
pub struct LocalizationDetector {
    language_names: HashSet<String>,
}

impl Default for LocalizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalizationDetector {
    /// A detector claiming the standard language-name set.
    pub fn new() -> Self {
        Self {
            language_names: DEFAULT_LANGUAGE_NAMES
                .iter()
                .map(|name| name.to_string())
                .collect(),
        }
    }

    /// A detector claiming exactly `names` as language names, replacing
    /// the standard set. Names are matched case-insensitively against the
    /// whole string value.
    pub fn with_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            language_names: names
                .into_iter()
                .map(|name| name.into().to_lowercase())
                .collect(),
        }
    }

    /// The language names the detector claims, in no particular order.
    pub(crate) fn language_names(&self) -> impl Iterator<Item = &str> {
        self.language_names.iter().map(String::as_str)
    }

    /// Whether the *whole* value is one of the claimed language names —
    /// case-insensitively. A language word inside a longer sentence is
    /// not the whole value and claims nothing.
    pub(crate) fn is_language_name(&self, value: &str) -> bool {
        self.language_names.contains(&value.to_lowercase())
    }

    /// Read the localization signals out of one function's mapped
    /// strings, reporting `None` when none of them carries a signal.
    ///
    /// One record per function, not per signal: `signal_kinds` names the
    /// kinds seen in the order the scan first saw each, `signals` keeps
    /// the signal strings in scan order (each value recorded once however
    /// often the function uses it), and `evidence` joins the lines that
    /// showed them. The reading never touches the classified records —
    /// it sits beside them as a separate structural claim, at
    /// [`LOCALIZATION_CONFIDENCE`].
    pub(crate) fn detect(
        &self,
        function: &str,
        candidates: &[MappedStringSignal<'_>],
    ) -> Option<LocalizationSignals> {
        let mut signal_kinds: Vec<LocalizationSignalKind> = Vec::new();
        let mut signals: Vec<String> = Vec::new();
        let mut evidence: Vec<&str> = Vec::new();
        for candidate in candidates {
            let Some(kind) = self.signal_kind(candidate) else {
                continue;
            };
            if signals.iter().any(|seen| seen == candidate.value) {
                continue;
            }
            if !signal_kinds.contains(&kind) {
                signal_kinds.push(kind);
            }
            signals.push(candidate.value.to_string());
            evidence.push(candidate.evidence);
        }
        if signals.is_empty() {
            return None;
        }
        Some(LocalizationSignals {
            function: function.to_string(),
            signal_kinds,
            signals,
            evidence: evidence.join(" "),
            confidence: Confidence::new(LOCALIZATION_CONFIDENCE),
        })
    }

    /// The signal kind one mapped string claims, if any. The whole-string
    /// gates run first; the non-ASCII gate additionally demands a decoded
    /// listing value and a user-facing classification.
    fn signal_kind(&self, candidate: &MappedStringSignal<'_>) -> Option<LocalizationSignalKind> {
        if self.is_language_name(candidate.value) {
            return Some(LocalizationSignalKind::LanguageName);
        }
        if locale_re().is_match(candidate.value) {
            return Some(LocalizationSignalKind::LocaleCode);
        }
        if candidate.from_listing
            && !candidate.value.is_ascii()
            && matches!(
                candidate.classification,
                StringClassification::UserVisible | StringClassification::Error
            )
        {
            return Some(LocalizationSignalKind::NonAsciiText);
        }
        None
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A body-parsed candidate: the value stands on its own, not read off
    /// the listing.
    fn candidate(value: &str, classification: StringClassification) -> MappedStringSignal<'_> {
        MappedStringSignal {
            value,
            classification,
            from_listing: false,
            evidence: "  pcVar = value;",
        }
    }

    /// A candidate whose value is one of the decoded program string
    /// listing's values.
    fn listing_candidate(
        value: &str,
        classification: StringClassification,
    ) -> MappedStringSignal<'_> {
        MappedStringSignal {
            from_listing: true,
            ..candidate(value, classification)
        }
    }

    /// A body-parsed candidate showing a specific line.
    fn with_evidence<'a>(
        value: &'a str,
        classification: StringClassification,
        evidence: &'a str,
    ) -> MappedStringSignal<'a> {
        MappedStringSignal {
            value,
            classification,
            from_listing: false,
            evidence,
        }
    }

    #[test]
    fn each_signal_kind_claims_its_shape() {
        let detector = LocalizationDetector::new();
        let signals = detector
            .detect(
                "FUN_18003ab00",
                &[
                    candidate("English", StringClassification::InternalIdentifier),
                    candidate("en-US", StringClassification::Generic),
                    listing_candidate("Welcome to the Café", StringClassification::UserVisible),
                    listing_candidate("Accès refusé", StringClassification::Error),
                ],
            )
            .expect("the three signal kinds claim the function");
        assert_eq!(signals.function, "FUN_18003ab00");
        assert_eq!(
            signals.signal_kinds,
            [
                LocalizationSignalKind::LanguageName,
                LocalizationSignalKind::LocaleCode,
                LocalizationSignalKind::NonAsciiText,
            ]
        );
        assert_eq!(
            signals.signals,
            ["English", "en-US", "Welcome to the Café", "Accès refusé",]
        );
        assert_eq!(signals.confidence, Confidence::new(60));
    }

    #[test]
    fn a_language_word_buried_in_a_sentence_claims_nothing() {
        // The whole-string gate: only a value that *is* the language name
        // reads as a selection signal.
        let detector = LocalizationDetector::new();
        assert!(
            detector
                .detect(
                    "FUN_18003ab00",
                    &[
                        candidate("Do you speak English?", StringClassification::Generic),
                        candidate("the French cancan", StringClassification::Generic),
                    ],
                )
                .is_none()
        );
        assert!(detector.is_language_name("English"));
        assert!(!detector.is_language_name("Do you speak English?"));
    }

    #[test]
    fn a_function_with_no_signals_reports_nothing() {
        let detector = LocalizationDetector::new();
        assert!(
            detector
                .detect(
                    "FUN_18003ab00",
                    &[
                        candidate("Journal.txt", StringClassification::FilePath),
                        candidate("%s: %d hits", StringClassification::FormatString),
                        candidate("Chat logging turned OFF.", StringClassification::DebugLog),
                    ],
                )
                .is_none()
        );
    }

    #[test]
    fn the_non_ascii_signal_reads_decoded_listing_values_only() {
        // The same user-facing value claims nothing when it is not one of
        // the program string listing's decoded values — an escaped body
        // literal cannot fake a signal the listing does not carry.
        let detector = LocalizationDetector::new();
        assert!(
            detector
                .detect(
                    "FUN_18003ab00",
                    &[candidate(
                        "Welcome to the Café",
                        StringClassification::UserVisible
                    )],
                )
                .is_none()
        );
        assert!(
            detector
                .detect(
                    "FUN_18003ab00",
                    &[candidate("caf\\xe9", StringClassification::UserVisible)],
                )
                .is_none()
        );
    }

    #[test]
    fn the_non_ascii_signal_claims_only_user_facing_classifications() {
        // High bytes on an internal identifier or a generic data value
        // say nothing about localization; only the UserVisible and Error
        // buckets do.
        let detector = LocalizationDetector::new();
        assert!(
            detector
                .detect(
                    "FUN_18003ab00",
                    &[
                        listing_candidate("日本語", StringClassification::Generic),
                        listing_candidate("ström_count", StringClassification::InternalIdentifier),
                    ],
                )
                .is_none()
        );
    }

    #[test]
    fn the_locale_shape_gate_is_the_whole_value() {
        let detector = LocalizationDetector::new();
        for claimed in ["en-US", "fr_FR", "pt_BR"] {
            let signals = detector
                .detect(
                    "FUN_18003ab00",
                    &[candidate(claimed, StringClassification::Generic)],
                )
                .unwrap_or_else(|| panic!("{claimed} reads as a locale code"));
            assert_eq!(signals.signal_kinds, [LocalizationSignalKind::LocaleCode]);
        }
        for rejected in ["en-USA", "EN-US", "english-US", "en", "en-US-UTF8"] {
            assert!(
                detector
                    .detect(
                        "FUN_18003ab00",
                        &[candidate(rejected, StringClassification::Generic)],
                    )
                    .is_none(),
                "{rejected} is not the xx-YY/xx_YY shape"
            );
        }
    }

    #[test]
    fn a_custom_language_name_set_replaces_the_default() {
        let detector = LocalizationDetector::with_names(["Klingon", "Romulan"]);
        assert!(detector.is_language_name("klingon"));
        assert!(!detector.is_language_name("English"));
        let signals = detector
            .detect(
                "FUN_18003ab00",
                &[
                    candidate("Klingon", StringClassification::InternalIdentifier),
                    candidate("English", StringClassification::InternalIdentifier),
                ],
            )
            .expect("the custom set claims its own name");
        assert_eq!(signals.signals, ["Klingon"]);
    }

    #[test]
    fn the_default_name_set_matches_case_insensitively() {
        let detector = LocalizationDetector::new();
        for name in ["English", "english", "FRENCH", "Japanese"] {
            assert!(detector.is_language_name(name), "{name} is a language");
        }
        assert!(detector.language_names().count() >= DEFAULT_LANGUAGE_NAMES.len());
    }

    #[test]
    fn one_finding_names_every_signal_once_however_often_used() {
        // One record per function, not per signal or per use: the two
        // language names and the locale code collapse into one reading,
        // each string named once, the kinds in first-seen order, and the
        // signal lines joined into the evidence.
        let detector = LocalizationDetector::new();
        let lines = [
            "pcVar1 = DAT_180129b00;",
            "pcVar2 = DAT_180129b10;",
            "pcVar3 = DAT_180129b00;",
            "pcVar4 = DAT_180129b20;",
        ];
        let candidates = [
            with_evidence("French", StringClassification::InternalIdentifier, lines[0]),
            with_evidence("en-US", StringClassification::Generic, lines[1]),
            with_evidence("French", StringClassification::InternalIdentifier, lines[2]),
            with_evidence(
                "English",
                StringClassification::InternalIdentifier,
                lines[3],
            ),
        ];
        let signals = detector
            .detect("FUN_18003ab00", &candidates)
            .expect("the function carries signals");
        assert_eq!(signals.signals, ["French", "en-US", "English"]);
        assert_eq!(
            signals.signal_kinds,
            [
                LocalizationSignalKind::LanguageName,
                LocalizationSignalKind::LocaleCode,
            ]
        );
        assert_eq!(
            signals.evidence,
            "pcVar1 = DAT_180129b00; pcVar2 = DAT_180129b10; pcVar4 = DAT_180129b20;"
        );
    }

    #[test]
    fn the_suggestion_names_the_rust_shape() {
        // The union renders the finding's suggestion from this constant;
        // pin the wording the prompt will carry.
        assert!(LOCALIZATION_SUGGESTION.contains("enum"));
        assert!(LOCALIZATION_SUGGESTION.contains("table"));
    }

    #[test]
    fn the_detector_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalizationDetector>();
    }
}
