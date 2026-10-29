//! Core data types for string and configuration context.
//!
//! This module holds the serialized shape of everything the string-context
//! scan produces:
//!
//! - `StringClassification`: the nine-category role a program string plays —
//!   format string, file path, resource name, error message, network, debug
//!   log, user-visible text, internal identifier, or generic.
//! - `StringSource`: how a string was tied to a function — read out of the
//!   decompiled body or found by an xref lookup.
//! - `FormatHint`: one format specifier's inferred Rust argument type.
//! - `ClassifiedString`, `FormatStringUse`: the per-function records — a
//!   string the function uses with its classification and purpose, and a
//!   format-string call with its inferred argument types.
//! - `LocalizationSignalKind`, `LocalizationSignals`: the localization
//!   reading — the signal kinds and strings one function's mapped strings
//!   carry.
//! - `CrossFunctionFlow`: the cross-function reading — a string one
//!   program function passes to another across a call boundary.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance. `Confidence` is
// the shared 0–100 evidence confidence score. This crate re-exports both so
// consumers can name them through this crate, the same way the typesdb,
// typeinfer, algorithm, memory, and sync crates do.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

use crate::cross_function::CROSS_FUNCTION_SUGGESTION;
use crate::format_str::summarize_hints;
use crate::localization::LOCALIZATION_SUGGESTION;

// ============================================================
// String classification
// ============================================================

/// The role a program string plays, out of nine categories.
///
/// The category says what the string is *for* — a `sprintf` format string,
/// a config-file path, or an error message shown to the user. The
/// translation prompt can then state the string's intent instead of
/// guessing it from an opaque `DAT_xxxxxxxx` reference.
/// [`classify`](crate::classify::StringClassifyEngine::classify) matches
/// patterns in priority order. If a string matches several pattern sets,
/// it gets the most informative category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringClassification {
    /// A `printf`-style format string that contains `%` specifiers.
    FormatString,
    /// A file or registry path, e.g. `Journal.txt` or `C:\game\cfg.ini`.
    FilePath,
    /// A resource or registry name, e.g. a bitmap resource or `HKEY_...` key.
    ResourceName,
    /// An error message, e.g. `Failed to open connection`.
    Error,
    /// A network address, URL, or protocol string.
    Network,
    /// A debug or log line, e.g. `Chat logging turned OFF`.
    DebugLog,
    /// Text shown to the user, e.g. a dialog label or prompt.
    UserVisible,
    /// An internal identifier or symbol name, e.g. a bare `LoggingOn`.
    InternalIdentifier,
    /// Plain string data with no stronger signal.
    Generic,
}

calxgloss_types::display_serde_label!(StringClassification {
    FormatString => "format_string",
    FilePath => "file_path",
    ResourceName => "resource_name",
    Error => "error",
    Network => "network",
    DebugLog => "debug_log",
    UserVisible => "user_visible",
    InternalIdentifier => "internal_identifier",
    Generic => "generic",
});

// ============================================================
// Mapping provenance
// ============================================================

/// How a string was tied to the function that uses it.
///
/// A body-parsed string was read directly out of the function's pseudo-C —
/// a literal, a resolved `DAT_` reference, or a format-function call. An
/// xref-only string was found by asking the analysis engine which
/// functions reference it; this is the fallback when the body parse found
/// nothing. The record keeps the provenance so a reviewer (or an evidence
/// confidence score) can rate body-parsed evidence above xref-only
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringSource {
    /// The string appeared in the function's decompiled body.
    BodyParse,
    /// The string was tied to the function by an `xrefs_to()` lookup.
    Xref,
}

// ============================================================
// Format hints
// ============================================================

/// One format specifier's inferred Rust argument type.
///
/// A hint says the format string contains the specifier
/// [`specifier`](Self::specifier) — e.g. `%s` or `%.2f` — as its
/// [`position`](Self::position)th argument (0-based; `%%` takes no
/// argument slot). It also says the original call passed an argument of
/// [`rust_type`](Self::rust_type) — `*const i8` for `%s`, `f32` for
/// `%.2f`. A prompt shows this list of hints in place of the argument
/// types the format string implies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatHint {
    /// The specifier as written in the format string, e.g. `%.2f`.
    pub specifier: String,
    /// The argument index the specifier fills, 0-based.
    pub position: usize,
    /// The Rust type the specifier's argument reads as, e.g. `*const i8`.
    pub rust_type: String,
}

// ============================================================
// Per-function records
// ============================================================

/// One string a function uses, with what it says and how it was found.
///
/// The record says the function references the string at
/// [`string_address`](Self::string_address), whose value is
/// [`string_value`](Self::string_value). The classifier read it as
/// [`classification`](Self::classification), which implies a one-line
/// [`purpose`](Self::purpose). The link to the function came through
/// [`source`](Self::source). The record also keeps the decompiled line or
/// xref that shows the use, as [`evidence`](Self::evidence), so a reviewer
/// (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedString {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The address the string is defined at, e.g. `0x180127cd8`.
    pub string_address: u64,
    /// The string's contents, e.g. `Journal.txt`.
    pub string_value: String,
    /// The category the classifier read the string as.
    pub classification: StringClassification,
    /// A one-line statement of what the string is for, e.g.
    /// `config file path`.
    pub purpose: String,
    /// Whether the use was read from the body or found by xref.
    pub source: StringSource,
    /// Evidence confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line or xref that shows the use, kept so a reviewer
    /// (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

/// One format-string call a function makes, with the argument types the
/// format string implies.
///
/// The record says the function calls a recognized format function —
/// `sprintf`, `snprintf`, `wsprintf` — with the format string at
/// [`string_address`](Self::string_address), whose value is
/// [`format_string`](Self::format_string). The [`call_site`](Self::call_site)
/// line is the decompiled call itself, and [`arg_types`](Self::arg_types)
/// holds the [`FormatHint`]s the specifiers imply, in argument order. The
/// translator therefore sees the argument types the original call passed —
/// the `*const i8` and `i32` behind `"%s: %d hits"` — instead of rewriting
/// the call without them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatStringUse {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The format string's contents, e.g. `%s: %d hits`.
    pub format_string: String,
    /// The address the format string is defined at, e.g. `0x180127cd8`.
    pub string_address: u64,
    /// The decompiled call line that shows the use.
    pub call_site: String,
    /// The inferred argument types, in argument order.
    pub arg_types: Vec<FormatHint>,
    /// Evidence confidence that the record is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Localization signals
// ============================================================

/// The kinds of localization signal the detector reads in a function's
/// strings.
///
/// Each kind is one shape that language machinery leaves in the string
/// listing. See
/// `localization`
/// for the checks that decide when each kind applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalizationSignalKind {
    /// The whole string value is a language name, e.g. `English`.
    LanguageName,
    /// The whole value matches the `xx-YY`/`xx_YY` locale shape, e.g.
    /// `en-US` or `fr_FR`.
    LocaleCode,
    /// A user-facing value that contains non-ASCII characters —
    /// accented Latin, CJK — read from the decoded program string
    /// listing.
    NonAsciiText,
}

/// One function's localization signals — the language machinery its
/// mapped strings reveal.
///
/// The record says the function uses strings with the signal kinds listed
/// in [`signal_kinds`](Self::signal_kinds), in the order the scan first
/// saw each kind. It names the signal strings themselves in
/// [`signals`](Self::signals), in scan order; each value appears once,
/// however often the function uses it. The lines that showed the signals
/// are joined into [`evidence`](Self::evidence), so a reviewer can check
/// the reading against the body. The evidence confidence sits visibly
/// below a directly classified record's: the claim is a pattern inference
/// over string shapes, and it is reported **beside** the classified
/// records — nothing here reclassifies them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizationSignals {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The signal kinds seen, in the order the scan first saw each.
    pub signal_kinds: Vec<LocalizationSignalKind>,
    /// The signal strings themselves, in scan order.
    pub signals: Vec<String>,
    /// The lines showing the signals, one per signal, joined.
    pub evidence: String,
    /// Evidence confidence that the record is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Cross-function string flow
// ============================================================

/// A string one program function passes to another across a call
/// boundary, recorded by the cross-function pass from the bodies the scan
/// keeps.
///
/// The record says [`passing_function`](Self::passing_function) calls
/// [`receiving_function`](Self::receiving_function) with
/// [`string_value`](Self::string_value) as an argument it can read — a
/// direct literal, or a `DAT_` that the string table resolves. The record
/// attaches to whichever of the two functions comes earlier in the
/// function listing (the callback-chain precedent), so one flow reads the
/// same however the listing orders the pair. The evidence is the passing
/// call's own line. The evidence confidence is the same as an in-body
/// call claim's: the call is explicit in a body the scan holds. There is
/// one record per (passing, receiving, string) triple, and the first
/// matching call site wins. A string passed to an import, or held in a
/// variable the mapper cannot resolve, produces no record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFunctionFlow {
    /// The function the record is attached to: the earlier of the two
    /// functions in listing order.
    pub function: String,
    /// The function that passes the string.
    pub passing_function: String,
    /// The function that receives it.
    pub receiving_function: String,
    /// The string that flows across the call boundary.
    pub string_value: String,
    /// The string's address in the program's string listing. It is 0
    /// when the body showed a direct literal that the listing gives no
    /// address for — the same convention the classified records use.
    pub string_address: u64,
    /// The passing call's own line.
    pub evidence: String,
    /// Evidence confidence that the record is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Finding union
// ============================================================

/// One string-context finding, whichever part of the scan made it.
///
/// Each part of the scan emits its own concrete records. The union is
/// what the persisted result carries, so one list can hold every finding
/// for a binary and a consumer reads the shared shape — function,
/// suggestion, evidence confidence, and evidence — without naming which
/// part produced it. The serde `kind` tag names the record shape in the
/// persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StringFinding {
    /// A string the function uses, classified into its category.
    Classified(ClassifiedString),
    /// A format-string call with the argument types the specifiers imply.
    FormatString(FormatStringUse),
    /// A function whose mapped strings carry localization signals —
    /// language names, locale codes, non-ASCII user-facing text.
    Localization(LocalizationSignals),
    /// A string one program function passes to another across a call
    /// boundary — the cross-function correlation.
    CrossFunction(CrossFunctionFlow),
}

impl StringFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            StringFinding::Classified(record) => &record.function,
            StringFinding::FormatString(record) => &record.function,
            StringFinding::Localization(record) => &record.function,
            StringFinding::CrossFunction(record) => &record.function,
        }
    }

    /// What the finding suggests about the function: the string's one-line
    /// purpose, the argument types the format string implies, or the Rust
    /// language-enum-plus-string-table shape the localization signals
    /// point at.
    pub fn suggestion(&self) -> String {
        match self {
            StringFinding::Classified(record) => record.purpose.clone(),
            StringFinding::FormatString(record) => summarize_hints(&record.arg_types),
            StringFinding::Localization(_) => LOCALIZATION_SUGGESTION.to_string(),
            StringFinding::CrossFunction(_) => CROSS_FUNCTION_SUGGESTION.to_string(),
        }
    }

    /// Evidence confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            StringFinding::Classified(record) => record.confidence,
            StringFinding::FormatString(record) => record.confidence,
            StringFinding::Localization(record) => record.confidence,
            StringFinding::CrossFunction(record) => record.confidence,
        }
    }

    /// The decompiled line or xref that supports the finding.
    pub fn evidence(&self) -> &str {
        match self {
            StringFinding::Classified(record) => &record.evidence,
            StringFinding::FormatString(record) => &record.call_site,
            StringFinding::Localization(record) => &record.evidence,
            StringFinding::CrossFunction(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `classified`, `format_string`,
    /// `localization`, or `cross_function` — naming the part of the
    /// scan behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            StringFinding::Classified(_) => "classified",
            StringFinding::FormatString(_) => "format_string",
            StringFinding::Localization(_) => "localization",
            StringFinding::CrossFunction(_) => "cross_function",
        }
    }

    /// What the finding names, spelled out for a report row: the string
    /// value itself, the format string behind the call, the signal
    /// strings the localization record saw, or the two functions and the
    /// string between them for the cross-function record.
    pub fn target(&self) -> String {
        match self {
            StringFinding::Classified(record) => record.string_value.clone(),
            StringFinding::FormatString(record) => record.format_string.clone(),
            StringFinding::Localization(record) => record.signals.join(", "),
            StringFinding::CrossFunction(record) => format!(
                "{}→{}:{}",
                record.passing_function, record.receiving_function, record.string_value
            ),
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data. The prompt gets the function the
/// finding is about, the role the string plays — its classification
/// category, or `format_string` — the Rust reading the finding suggests,
/// and the evidence confidence and evidence behind the claim. Whichever
/// part of the scan produced the finding, the escalate prompt shows the
/// hypothesis and how strongly it was made.
impl From<&StringFinding> for calxgloss_prompts::StringContextInfo {
    fn from(finding: &StringFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: match finding {
                StringFinding::Classified(record) => record.classification.to_string(),
                StringFinding::FormatString(_) => "format_string".to_string(),
                StringFinding::Localization(_) => "localization".to_string(),
                StringFinding::CrossFunction(_) => "cross_function".to_string(),
            },
            suggestion: finding.suggestion(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The string-context result for one binary — the document persisted to
/// `re/analysis/stringctx/{dll}.json`.
///
/// The findings are the scan's output, in scan order: function by
/// function. Within one function, the classified strings come first,
/// then the format-string calls, then the localization reading. After
/// every function come the cross-function string flows, in listing
/// order. This stable order lets two scans of the same program diff
/// cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringContextResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the scan made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<StringFinding>,
}

impl StringContextResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &StringFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CLASSIFICATIONS: [StringClassification; 9] = [
        StringClassification::FormatString,
        StringClassification::FilePath,
        StringClassification::ResourceName,
        StringClassification::Error,
        StringClassification::Network,
        StringClassification::DebugLog,
        StringClassification::UserVisible,
        StringClassification::InternalIdentifier,
        StringClassification::Generic,
    ];

    #[test]
    fn classifications_display_their_serde_labels() {
        for classification in ALL_CLASSIFICATIONS {
            let label = serde_json::to_value(classification).unwrap();
            assert_eq!(classification.to_string(), label.as_str().unwrap());
        }
        assert_eq!(
            StringClassification::FormatString.to_string(),
            "format_string"
        );
        assert_eq!(
            StringClassification::InternalIdentifier.to_string(),
            "internal_identifier"
        );
    }

    #[test]
    fn a_classified_string_serde_round_trips() {
        let record = ClassifiedString {
            function: "FUN_18003ab00".into(),
            string_address: 0x180127cd8,
            string_value: "Journal.txt".into(),
            classification: StringClassification::FilePath,
            purpose: "file path".into(),
            source: StringSource::BodyParse,
            confidence: Confidence::new(70),
            evidence: "lFile = CreateFileA(\"Journal.txt\",...);".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        // The category and provenance serialize snake_case, and the
        // evidence confidence is a plain number, matching the
        // workspace's serde convention.
        assert!(json.contains("\"classification\":\"file_path\""));
        assert!(json.contains("\"source\":\"body_parse\""));
        assert!(json.contains("\"confidence\":70"));
        let back: ClassifiedString = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_classified_string_record_names_its_fields() {
        let record = ClassifiedString {
            function: "FUN_18003ab00".into(),
            string_address: 0x180128cf0,
            string_value: "Chat logging turned OFF.".into(),
            classification: StringClassification::DebugLog,
            purpose: "debug or log message".into(),
            source: StringSource::Xref,
            confidence: Confidence::new(60),
            evidence: "xref from 0x180006f04 in FUN_180006da0 [DATA]".into(),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["string_address"], 0x180128cf0u64);
        assert_eq!(json["string_value"], "Chat logging turned OFF.");
        assert_eq!(json["classification"], "debug_log");
        assert_eq!(json["purpose"], "debug or log message");
        assert_eq!(json["source"], "xref");
        assert_eq!(json["confidence"], 60);
    }

    #[test]
    fn a_format_string_use_serde_round_trips() {
        let record = FormatStringUse {
            function: "FUN_18003ab00".into(),
            format_string: "%s: %d hits".into(),
            string_address: 0x180127cd8,
            call_site: "sprintf(local_10, \"%s: %d hits\", name, count);".into(),
            arg_types: vec![
                FormatHint {
                    specifier: "%s".into(),
                    position: 0,
                    rust_type: "*const i8".into(),
                },
                FormatHint {
                    specifier: "%d".into(),
                    position: 1,
                    rust_type: "i32".into(),
                },
            ],
            confidence: Confidence::new(70),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"format_string\":\"%s: %d hits\""));
        assert!(json.contains("\"specifier\":\"%s\""));
        assert!(json.contains("\"rust_type\":\"*const i8\""));
        let back: FormatStringUse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    fn classified_record() -> ClassifiedString {
        ClassifiedString {
            function: "FUN_18003ab00".into(),
            string_address: 0x180127cd8,
            string_value: "Journal.txt".into(),
            classification: StringClassification::FilePath,
            purpose: "config file path".into(),
            source: StringSource::BodyParse,
            confidence: Confidence::new(70),
            evidence: "lFile = CreateFileA(\"Journal.txt\",...);".into(),
        }
    }

    fn format_use_record() -> FormatStringUse {
        FormatStringUse {
            function: "FUN_18003ab00".into(),
            format_string: "%s: %d hits".into(),
            string_address: 0x180127cd8,
            call_site: "sprintf(local_10, \"%s: %d hits\", name, count);".into(),
            arg_types: vec![
                FormatHint {
                    specifier: "%s".into(),
                    position: 0,
                    rust_type: "*const i8".into(),
                },
                FormatHint {
                    specifier: "%d".into(),
                    position: 1,
                    rust_type: "i32".into(),
                },
            ],
            confidence: Confidence::new(70),
        }
    }

    fn localization_signals() -> LocalizationSignals {
        LocalizationSignals {
            function: "FUN_18003ab00".into(),
            signal_kinds: vec![
                LocalizationSignalKind::LanguageName,
                LocalizationSignalKind::LocaleCode,
            ],
            signals: vec!["English".into(), "en-US".into()],
            evidence: "pcVar1 = (char *)DAT_180129b00; puVar2 = DAT_180129b10;".into(),
            confidence: Confidence::new(60),
        }
    }

    fn cross_function_flow() -> CrossFunctionFlow {
        CrossFunctionFlow {
            function: "FUN_18003ab00".into(),
            passing_function: "FUN_18003ab00".into(),
            receiving_function: "FUN_18003e750".into(),
            string_value: "Journal.txt".into(),
            string_address: 0x180127cd8,
            evidence: "FUN_18003e750(\"Journal.txt\");".into(),
            confidence: Confidence::new(70),
        }
    }

    #[test]
    fn a_classified_finding_serde_round_trips_under_its_kind_tag() {
        let finding = StringFinding::Classified(classified_record());
        let json = serde_json::to_string(&finding).expect("classified finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"classified\""));
        assert!(json.contains("\"classification\":\"file_path\""));
        let back: StringFinding =
            serde_json::from_str(&json).expect("classified finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_format_string_finding_serde_round_trips_under_its_kind_tag() {
        let finding = StringFinding::FormatString(format_use_record());
        let json = serde_json::to_string(&finding).expect("format finding should serialize");
        assert!(json.contains("\"kind\":\"format_string\""));
        assert!(json.contains("\"format_string\":\"%s: %d hits\""));
        let back: StringFinding =
            serde_json::from_str(&json).expect("format finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_localization_finding_serde_round_trips_under_its_kind_tag() {
        let finding = StringFinding::Localization(localization_signals());
        let json = serde_json::to_string(&finding).expect("localization finding should serialize");
        assert!(json.contains("\"kind\":\"localization\""));
        assert!(json.contains("\"signal_kinds\":[\"language_name\",\"locale_code\"]"));
        assert!(json.contains("\"signals\":[\"English\",\"en-US\"]"));
        assert!(json.contains("\"confidence\":60"));
        let back: StringFinding =
            serde_json::from_str(&json).expect("localization finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_cross_function_finding_serde_round_trips_under_its_kind_tag() {
        let finding = StringFinding::CrossFunction(cross_function_flow());
        let json =
            serde_json::to_string(&finding).expect("cross-function finding should serialize");
        assert!(json.contains("\"kind\":\"cross_function\""));
        assert!(json.contains("\"passing_function\":\"FUN_18003ab00\""));
        assert!(json.contains("\"receiving_function\":\"FUN_18003e750\""));
        assert!(json.contains("\"string_value\":\"Journal.txt\""));
        assert!(json.contains("\"confidence\":70"));
        let back: StringFinding =
            serde_json::from_str(&json).expect("cross-function finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            StringFinding::Classified(classified_record()),
            StringFinding::FormatString(format_use_record()),
            StringFinding::Localization(localization_signals()),
            StringFinding::CrossFunction(cross_function_flow()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        assert_eq!(findings[0].confidence(), Confidence::new(70));
        assert_eq!(findings[1].confidence(), Confidence::new(70));
        assert_eq!(findings[2].confidence(), Confidence::new(60));
        assert_eq!(findings[3].confidence(), Confidence::new(70));
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "classified",
                "format_string",
                "localization",
                "cross_function"
            ]
        );
        let suggestions: Vec<String> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(
            suggestions,
            vec![
                "config file path",
                "`*const i8`, `i32`",
                "model the language switch as a Rust enum with the localized strings held in a table",
                "the receiving parameter translates as a string type (`*const i8`/`&str`) and the caller's payload is that string",
            ]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "Journal.txt",
                "%s: %d hits",
                "English, en-US",
                "FUN_18003ab00→FUN_18003e750:Journal.txt",
            ]
        );
    }

    #[test]
    fn a_string_context_result_serde_round_trips() {
        let result = StringContextResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
                coverage: None,
            },
            findings: vec![
                StringFinding::Classified(classified_record()),
                StringFinding::FormatString(format_use_record()),
                StringFinding::Localization(localization_signals()),
                StringFinding::CrossFunction(cross_function_flow()),
            ],
        };
        let json = serde_json::to_string(&result).expect("string context result should serialize");
        let back: StringContextResult =
            serde_json::from_str(&json).expect("string context result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents saved before a finding kind existed still load, and
        // an empty scan stays small on disk.
        let result = StringContextResult::new(ScanMetadata::new("eqmain.dll"));
        let json =
            serde_json::to_string(&result).expect("empty string context result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: StringContextResult =
            serde_json::from_str(&json).expect("empty string context result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = StringFinding::Classified(ClassifiedString {
            function: "FUN_18003e750".into(),
            ..classified_record()
        });
        let result = StringContextResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![
                other.clone(),
                StringFinding::Classified(classified_record()),
            ],
        };
        let found: Vec<&StringFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }
}
