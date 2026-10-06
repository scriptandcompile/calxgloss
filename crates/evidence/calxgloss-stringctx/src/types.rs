//! Core data types for string and configuration context.
//!
//! This module holds the serialized shape of everything the string-context
//! engines produce:
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
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm,
// memory, and sync convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// String classification
// ============================================================

/// The role a program string plays, out of nine categories.
///
/// The category says what the string is *for* — a `sprintf` format string,
/// a config-file path, an error message shown to the user — so the
/// translation prompt can name the string's intent instead of guessing it
/// from an opaque `DAT_xxxxxxxx` reference. [`classify`](crate::classify::StringClassifyEngine::classify)
/// assigns the category by priority-ordered pattern matching; a string that
/// matches several pattern sets lands in the most informative bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringClassification {
    /// A `printf`-style format string carrying `%` specifiers.
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
/// a literal, a resolved `DAT_` reference, or a format-function call — while
/// an xref-only string was found by asking Ghidra which functions reference
/// it, the fallback for functions whose body parse found nothing. The
/// provenance is kept so a reviewer (or a confidence score) can weigh
/// body-parsed evidence above xref-only evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringSource {
    /// The string appeared in the function's decompiled body.
    BodyParse,
    /// The string was tied to the function by a `get_xrefs_to` lookup.
    Xref,
}

// ============================================================
// Format hints
// ============================================================

/// One format specifier's inferred Rust argument type.
///
/// A hint says the format string carries the specifier
/// [`specifier`](Self::specifier) — e.g. `%s` or `%.2f` — as its
/// [`position`](Self::position)th argument (0-based, `%%` taking no
/// argument slot), and that the original call passed an argument of
/// [`rust_type`](Self::rust_type) — `*const i8` for `%s`, `f32` for
/// `%.2f`. The list of hints is what the prompt shows in place of the
/// argument types the format string implies.
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
/// A record says the function references the string at
/// [`string_address`](Self::string_address) whose value is
/// [`string_value`](Self::string_value); the classifier read it as
/// [`classification`](Self::classification) — carrying the one-line
/// [`purpose`](Self::purpose) that category implies — and the tie to the
/// function came through [`source`](Self::source). The decompiled line or
/// xref that shows the use is kept as [`evidence`](Self::evidence) so a
/// reviewer (or a translation prompt) can check the reasoning.
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
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line or xref that shows the use, kept so a reviewer
    /// (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

/// One format-string call a function makes, with the argument types the
/// format string implies.
///
/// A record says the function calls a recognized format function —
/// `sprintf`, `snprintf`, `wsprintf` — passing the format string at
/// [`string_address`](Self::string_address) whose value is
/// [`format_string`](Self::format_string); the [`call_site`](Self::call_site)
/// line is the decompiled call itself, and [`arg_types`](Self::arg_types)
/// are the [`FormatHint`]s the specifiers imply, in argument order. The
/// translator sees the argument types the original call carried — the
/// `*const i8` and `i32` behind `"%s: %d hits"` — instead of transliterating
/// the call blind.
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
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Finding union
// ============================================================

/// One string-context finding, whichever engine made it.
///
/// The engines emit the concrete records; the union is what the persisted
/// result carries, so one list can hold every finding for a binary and a
/// consumer reads the shared shape — function, suggestion, confidence,
/// evidence — without naming which engine produced it. The serde `kind`
/// tag names the record shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StringFinding {
    /// A string the function uses, classified into its category.
    Classified(ClassifiedString),
    /// A format-string call with the argument types the specifiers imply.
    FormatString(FormatStringUse),
}

impl StringFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            StringFinding::Classified(record) => &record.function,
            StringFinding::FormatString(record) => &record.function,
        }
    }

    /// What the finding suggests about the function: the string's one-line
    /// purpose, or the argument types the format string implies.
    pub fn suggestion(&self) -> String {
        match self {
            StringFinding::Classified(record) => record.purpose.clone(),
            StringFinding::FormatString(record) => {
                let types: Vec<&str> = record
                    .arg_types
                    .iter()
                    .map(|hint| hint.rust_type.as_str())
                    .collect();
                format!("({})", types.join(", "))
            }
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            StringFinding::Classified(record) => record.confidence,
            StringFinding::FormatString(record) => record.confidence,
        }
    }

    /// The decompiled line or xref that supports the finding.
    pub fn evidence(&self) -> &str {
        match self {
            StringFinding::Classified(record) => &record.evidence,
            StringFinding::FormatString(record) => &record.call_site,
        }
    }

    /// The serde `kind` tag — `classified` or `format_string` — naming
    /// the engine behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            StringFinding::Classified(_) => "classified",
            StringFinding::FormatString(_) => "format_string",
        }
    }

    /// What the finding names, spelled for a report row: the string value
    /// itself, or the format string behind the call.
    pub fn target(&self) -> String {
        match self {
            StringFinding::Classified(record) => record.string_value.clone(),
            StringFinding::FormatString(record) => record.format_string.clone(),
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the role
/// the string plays — its classification category, or `format_string` —
/// the Rust reading the finding suggests, and the confidence and
/// evidence behind the claim, so the escalate prompt shows the
/// hypothesis and how strongly it was made, whichever engine produced
/// it.
impl From<&StringFinding> for calxgloss_prompts::StringContextInfo {
    fn from(finding: &StringFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: match finding {
                StringFinding::Classified(record) => record.classification.to_string(),
                StringFinding::FormatString(_) => "format_string".to_string(),
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
/// The findings are the scan's outputs in scan order: function by
/// function, and within one function the classified strings first and
/// then the format-string calls. The stable order means two scans of the
/// same program diff cleanly.
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
        // The category and provenance serialize snake_case and the
        // confidence as a plain number, matching the workspace's serde
        // convention.
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
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            StringFinding::Classified(classified_record()),
            StringFinding::FormatString(format_use_record()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(finding.confidence(), Confidence::new(70));
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["classified", "format_string"]);
        let suggestions: Vec<String> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(suggestions, vec!["config file path", "(*const i8, i32)"]);
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(targets, vec!["Journal.txt", "%s: %d hits"]);
    }

    #[test]
    fn a_string_context_result_serde_round_trips() {
        let result = StringContextResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                StringFinding::Classified(classified_record()),
                StringFinding::FormatString(format_use_record()),
            ],
        };
        let json = serde_json::to_string(&result).expect("string context result should serialize");
        let back: StringContextResult =
            serde_json::from_str(&json).expect("string context result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
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
