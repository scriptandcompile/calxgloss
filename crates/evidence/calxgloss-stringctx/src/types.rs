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
}
