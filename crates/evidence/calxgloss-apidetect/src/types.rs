//! Core data types for library and API identification.
//!
//! This module holds the serialized shape of everything the API detectors
//! produce:
//!
//! - `ApiSignature`: a binary-level import-table record — one entry with
//!   its library and Rust crate suggestion when identified.
//! - `ApiUsage`: a function-level record — an API the function reaches
//!   directly or through its call graph, with the call path as evidence.
//! - `ApiFinding`: the union over the two record kinds — one finding
//!   whichever detector made it — serde-tagged by `kind`.
//!
//! All types derive `Serialize`/`Deserialize`. `Confidence` is the shared
//! 0–100 evidence score and `ScanMetadata` the shared per-binary scan
//! provenance; both are re-exported so consumers name them through this
//! crate, matching the sync, typeinfer, and memory convention.

pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Import-table records
// ============================================================

/// One import-table entry, identified or not.
///
/// A signature says the binary imports the API spelled [`api`](Self::api);
/// when the name is in the [`MappingDatabase`](crate::lib_mapping::MappingDatabase),
/// [`library`](Self::library) names the library it belongs to and
/// [`rust_crate`](Self::rust_crate) the crate standing in for it.
/// Unidentified and ordinal-only imports are kept as entries with both
/// fields `None` — the import table is reported whole, not filtered to
/// what was recognized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSignature {
    /// The API name as the import table spells it, e.g. `inflate`.
    pub api: String,
    /// The library the API belongs to, e.g. `zlib`, when identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// The Rust crate standing in for the API, e.g. `flate2`, when
    /// identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_crate: Option<String>,
    /// Confidence that the identification is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Function-level records
// ============================================================

/// One API a function reaches, with the call path that reaches it.
///
/// A usage says the function [`function`](Self::function) calls — or
/// transitively reaches through its call graph — the API spelled
/// [`api`](Self::api), belonging to [`library`](Self::library) and
/// standing in for [`rust_crate`](Self::rust_crate). A direct call is a
/// stronger claim than a transitive path, which the
/// [`direct`](Self::direct) flag and the confidence carry; the call path
/// itself is kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiUsage {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The API the function reaches, e.g. `inflate`.
    pub api: String,
    /// The library the API belongs to, e.g. `zlib`.
    pub library: String,
    /// The Rust crate standing in for the API, e.g. `flate2`.
    pub rust_crate: String,
    /// Whether the function calls the API directly rather than through
    /// intermediate functions.
    pub direct: bool,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The call path that reaches the API, e.g.
    /// `FUN_a → FUN_b → inflate`, kept so a reviewer (or a translation
    /// prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One API finding, whichever detector made it.
///
/// The import-table scanner emits binary-level [`ApiSignature`] records;
/// the summary detector emits function-level [`ApiUsage`] records. The
/// union is what the persisted result carries, so one list holds every
/// finding for a binary and a consumer reads the shared shape — API,
/// library, crate suggestion, confidence, evidence — without naming
/// which detector produced it. The serde `kind` tag names the record
/// shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiFinding {
    /// A binary-level import-table entry.
    Import(ApiSignature),
    /// A function-level API usage through the call graph.
    ApiUsage(ApiUsage),
}

impl ApiFinding {
    /// The function the finding is about — empty for a binary-level
    /// import entry.
    pub fn function(&self) -> &str {
        match self {
            ApiFinding::Import(_) => "",
            ApiFinding::ApiUsage(record) => &record.function,
        }
    }

    /// The API the finding names, spelled for a report row.
    pub fn target(&self) -> &str {
        match self {
            ApiFinding::Import(record) => &record.api,
            ApiFinding::ApiUsage(record) => &record.api,
        }
    }

    /// The library the API belongs to, when identified.
    pub fn library(&self) -> Option<&str> {
        match self {
            ApiFinding::Import(record) => record.library.as_deref(),
            ApiFinding::ApiUsage(record) => Some(&record.library),
        }
    }

    /// The Rust crate standing in for the API, when identified.
    pub fn rust_crate(&self) -> Option<&str> {
        match self {
            ApiFinding::Import(record) => record.rust_crate.as_deref(),
            ApiFinding::ApiUsage(record) => Some(&record.rust_crate),
        }
    }

    /// The crate suggestion, spelled for prompt rows — empty when the
    /// API was never identified.
    pub fn suggestion(&self) -> String {
        self.rust_crate().unwrap_or_default().to_string()
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ApiFinding::Import(record) => record.confidence,
            ApiFinding::ApiUsage(record) => record.confidence,
        }
    }

    /// The evidence behind the finding: the call path for a usage, the
    /// API name itself for a binary-level import entry.
    pub fn evidence(&self) -> String {
        match self {
            ApiFinding::Import(record) => record.api.clone(),
            ApiFinding::ApiUsage(record) => record.evidence.clone(),
        }
    }

    /// The serde `kind` tag — `import` or `api_usage` — naming the
    /// detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ApiFinding::Import(_) => "import",
            ApiFinding::ApiUsage(_) => "api_usage",
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// Everything one API-identification scan found for one binary.
///
/// The document the [`ApiPersistor`](crate::persist::ApiPersistor) files
/// under `re/analysis/apidetect/`, and the cache a caller loads instead
/// of re-scanning: the binary-level import entries first, in listing
/// order, then the function-level usages, function by function in call
/// graph order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDetectionResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ApiFinding>,
}

impl ApiDetectionResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00` —
    /// its usages, and only its usages: a binary-level import entry
    /// belongs to the binary, not to any function.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &ApiFinding> {
        self.findings
            .iter()
            .filter(move |finding| !finding.function().is_empty() && finding.function() == function)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Prompt shape
// ============================================================

/// One API finding in the shape an escalation prompt reads.
///
/// The prompts crate owns the struct (like `ConcurrencyInfo` for sync
/// findings); the conversion lives here so the finding's own accessors
/// carry the mapping. An import entry becomes a row with an empty
/// function and `kind = "import"`; a usage carries its call path and
/// `kind = "direct"` or `"transitive"`.
impl From<&ApiFinding> for calxgloss_prompts::ApiInfo {
    fn from(finding: &ApiFinding) -> Self {
        let kind = match finding {
            ApiFinding::Import(_) => "import",
            ApiFinding::ApiUsage(record) => {
                if record.direct {
                    "direct"
                } else {
                    "transitive"
                }
            }
        };
        calxgloss_prompts::ApiInfo {
            function: finding.function().to_string(),
            api: finding.target().to_string(),
            library: finding.library().unwrap_or("").to_string(),
            suggestion: finding.rust_crate().unwrap_or("").to_string(),
            kind: kind.to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage() -> ApiUsage {
        ApiUsage {
            function: "FUN_18003ab00".into(),
            api: "inflate".into(),
            library: "zlib".into(),
            rust_crate: "flate2".into(),
            direct: false,
            confidence: Confidence::new(60),
            evidence: "FUN_18003ab00 → FUN_18003c000 → inflate".into(),
        }
    }

    #[test]
    fn import_finding_reads_through_the_union_accessors() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "CreateFileA".into(),
            library: Some("Win32".into()),
            rust_crate: Some("windows / std::fs".into()),
            confidence: Confidence::new(90),
        });
        assert_eq!(finding.function(), "");
        assert_eq!(finding.target(), "CreateFileA");
        assert_eq!(finding.library(), Some("Win32"));
        assert_eq!(finding.rust_crate(), Some("windows / std::fs"));
        assert_eq!(finding.confidence(), Confidence::new(90));
        assert_eq!(finding.evidence(), "CreateFileA");
        assert_eq!(finding.kind(), "import");
    }

    #[test]
    fn unidentified_import_finding_has_no_library() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "VendorSpecialFunction".into(),
            library: None,
            rust_crate: None,
            confidence: Confidence::new(0),
        });
        assert_eq!(finding.library(), None);
        assert_eq!(finding.rust_crate(), None);
    }

    #[test]
    fn usage_finding_reads_through_the_union_accessors() {
        let finding = ApiFinding::ApiUsage(usage());
        assert_eq!(finding.function(), "FUN_18003ab00");
        assert_eq!(finding.target(), "inflate");
        assert_eq!(finding.library(), Some("zlib"));
        assert_eq!(finding.rust_crate(), Some("flate2"));
        assert_eq!(finding.confidence(), Confidence::new(60));
        assert_eq!(
            finding.evidence(),
            "FUN_18003ab00 → FUN_18003c000 → inflate"
        );
        assert_eq!(finding.kind(), "api_usage");
    }

    #[test]
    fn findings_round_trip_through_serde_with_the_kind_tag() {
        let findings = vec![
            ApiFinding::Import(ApiSignature {
                api: "inflate".into(),
                library: Some("zlib".into()),
                rust_crate: Some("flate2".into()),
                confidence: Confidence::new(90),
            }),
            ApiFinding::ApiUsage(usage()),
        ];
        let json = serde_json::to_string(&findings).unwrap();
        let back: Vec<ApiFinding> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, findings);
        assert!(json.contains(r#""kind":"import""#));
        assert!(json.contains(r#""kind":"api_usage""#));
    }

    #[test]
    fn import_finding_converts_to_a_prompt_row() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "inflate".into(),
            library: Some("zlib".into()),
            rust_crate: Some("flate2".into()),
            confidence: Confidence::new(90),
        });
        let info = calxgloss_prompts::ApiInfo::from(&finding);
        assert_eq!(info.function, "");
        assert_eq!(info.api, "inflate");
        assert_eq!(info.library, "zlib");
        assert_eq!(info.suggestion, "flate2");
        assert_eq!(info.kind, "import");
        assert_eq!(info.confidence, 90);
    }

    #[test]
    fn usage_finding_converts_to_a_prompt_row_with_its_call_path() {
        let finding = ApiFinding::ApiUsage(usage());
        let info = calxgloss_prompts::ApiInfo::from(&finding);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "transitive");
        assert_eq!(info.evidence, "FUN_18003ab00 → FUN_18003c000 → inflate");

        let direct = ApiFinding::ApiUsage(ApiUsage {
            direct: true,
            ..usage()
        });
        assert_eq!(calxgloss_prompts::ApiInfo::from(&direct).kind, "direct");
    }
}
