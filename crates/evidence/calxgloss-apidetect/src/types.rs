//! Core data types for library and API identification.
//!
//! This module holds the serialized shape of everything the API detectors
//! produce:
//!
//! - `ApiSignature`: a binary-level import-table record — one entry with
//!   its library, Rust crate suggestion, and API category with feature
//!   flags when identified.
//! - `ApiUsage`: a function-level record — an API the function reaches
//!   directly or through its call graph, with the call path as evidence.
//! - `PlatformDivergence`: a binary-level record — the binary imports
//!   both a Win32-family and a POSIX/stdio-family API, so the Rust
//!   shape is cfg-gated calls, not both families transliterated
//!   unconditionally.
//! - `ComInterface`: a binary-level record — the binary drives a COM
//!   interface. A decorated import name supplies the interface name
//!   when one can be recovered. The record holds the method listing
//!   the scan saw, and the Rust shape is a trait with those methods.
//! - `ApiFinding`: the union over the record kinds — one finding
//!   whichever detector made it — serde-tagged by `kind`.
//!
//! All types derive `Serialize`/`Deserialize`. `Confidence` is the
//! shared 0–100 evidence score, and `ScanMetadata` is the shared
//! per-binary scan provenance. Both are re-exported so consumers name
//! them through this crate, as the sync, typeinfer, and memory crates
//! do.

pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

use crate::com::{COM_INTERFACE_SUGGESTION, COM_RUNTIME_SUGGESTION};
use crate::divergence::DIVERGENCE_SUGGESTION;

// ============================================================
// Import-table records
// ============================================================

/// One import-table entry, identified or not.
///
/// The entry says the binary imports the API spelled [`api`](Self::api).
/// When the name is in the [`MappingDatabase`](crate::lib_mapping::MappingDatabase),
/// [`library`](Self::library) records the library it belongs to and
/// [`rust_crate`](Self::rust_crate) the crate standing in for it. The
/// entry also records its [`category`](Self::category) and the crate's
/// [`features`](Self::features) when the mapping provides them.
/// Unidentified and ordinal-only imports are kept as entries with both
/// identity fields `None` and no category — the import table is
/// reported whole, not filtered to what was recognized, and enrichment
/// never adds a category the evidence does not support.
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
    /// The API category the library entry records, spelled with the
    /// PAL `ApiCategory` display names (e.g. `Win32Core`, `zlib`),
    /// when the mapping provides one — unidentified and ordinal-only
    /// imports stay category-less. Optional on disk so documents
    /// persisted before the enrichment load unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Feature flags the crate suggestion comes with, e.g. `png` for
    /// `image`, empty when the suggestion needs none. Skipped when
    /// empty so plain records stay byte-identical on disk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Confidence that the identification is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// Function-level records
// ============================================================

/// One API a function reaches, with the call path that reaches it.
///
/// The usage says the function [`function`](Self::function) calls the
/// API spelled [`api`](Self::api) — directly, or transitively through
/// its call graph. The API belongs to [`library`](Self::library) and
/// stands in for [`rust_crate`](Self::rust_crate). A direct call is a
/// stronger claim than a transitive path; the [`direct`](Self::direct)
/// flag and the confidence record that difference. The call path
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
    /// The API category the library entry records, spelled with the
    /// PAL `ApiCategory` display names (e.g. `Win32Core`, `zlib`),
    /// when the mapping provides one. Optional on disk so documents
    /// persisted before the enrichment load unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Feature flags the crate suggestion comes with, e.g. `png` for
    /// `image`, empty when the suggestion needs none. Skipped when
    /// empty so plain records stay byte-identical on disk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
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
// Platform-divergence records
// ============================================================

/// The binary-level claim that the binary uses two platform API
/// families at once.
///
/// A divergence says the import table has at least one import whose
/// mapping category indicates the Win32 family *and* at least one
/// import whose category indicates the POSIX family (the `POSIX` and
/// `stdio` categories). That is the gate the
/// [`divergence`](crate::divergence) detector checks on the
/// classified import listing. [`families`](Self::families) holds both
/// families as the category names that triggered the claim, and
/// [`evidence`](Self::evidence) lists the triggering imports from both
/// sides, so a reviewer can check the claim against the import table.
/// The Rust shape the finding points
/// at is cfg-gated calls; the suggestion accessor gives that wording.
/// A purely Win32 or purely POSIX binary claims nothing, so the record
/// never exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDivergence {
    /// The platform families seen, spelled with the mapping categories
    /// that triggered the claim — the Win32 side first, e.g.
    /// `["Win32Core", "POSIX"]`.
    pub families: Vec<String>,
    /// The imports that triggered the claim, from both sides, each
    /// spelled `api (category)`, the Win32 side first and each side in
    /// import-listing order.
    pub evidence: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
}

// ============================================================
// COM interface records
// ============================================================

/// The binary-level claim that the binary drives the COM component
/// model — either a named interface recovered from decorated import
/// names, or the COM runtime itself when no interface name is
/// recoverable.
///
/// The [com](crate::com) detector reads its signals from the
/// classified import listing and the call-graph names the scan
/// already holds: known COM runtime imports, the IUnknown-shape method
/// names, and interface-decorated import names. When a decorated name
/// recovers an interface name, [`interface`](Self::interface) holds
/// it, [`methods`](Self::methods) lists the method names seen for it,
/// and [`evidence`](Self::evidence) keeps the decorated names so a
/// reviewer can check the recovery against the import table. When no
/// name is recoverable, one runtime-level claim records the COM
/// signals seen with `interface` `None`, at a visibly lower confidence
/// than a named claim. A binary with no COM signals claims nothing, so
/// the record never exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComInterface {
    /// The interface name recovered from a decorated import name, e.g.
    /// `IDataSource` from `?QueryInterface@IDataSource@@…` — `None` for
    /// a runtime-level claim, which has no name to recover. Optional on
    /// disk so a runtime-level claim serializes without the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// The method names seen for the interface, in first-seen order,
    /// e.g. `["QueryInterface", "AddRef", "Release"]` — empty for a
    /// runtime-level claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// The evidence behind the claim: the decorated names the interface
    /// was recovered from, joined `", "`, in listing order — or the COM
    /// signals seen, for a runtime-level claim.
    pub evidence: String,
    /// Confidence that the record is right, 0–100 — a named-interface
    /// claim sits visibly above a runtime-level one.
    pub confidence: Confidence,
}

// ============================================================
// Finding union
// ============================================================

/// One API finding, whichever detector made it.
///
/// The import-table scanner emits binary-level [`ApiSignature`]
/// records. When the imports mix platform families, the
/// [divergence](crate::divergence) detector emits one binary-level
/// [`PlatformDivergence`] record. When the imports and call-graph
/// names show COM signals, the [com](crate::com) detector emits
/// binary-level [`ComInterface`] records. The summary detector emits
/// function-level [`ApiUsage`] records. The union is what the
/// persisted result holds, so one list carries every finding for a
/// binary and a consumer reads the shared shape — API, library, crate
/// suggestion, confidence, evidence — without needing to know which
/// detector produced it. The serde `kind` tag records the record
/// shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiFinding {
    /// A binary-level import-table entry.
    Import(ApiSignature),
    /// A binary-level claim that the imports mix Win32 and POSIX/stdio
    /// families.
    PlatformDivergence(PlatformDivergence),
    /// A binary-level claim that the binary drives a COM interface or
    /// the COM runtime.
    ComInterface(ComInterface),
    /// A function-level API usage through the call graph.
    ApiUsage(ApiUsage),
}

impl ApiFinding {
    /// The function the finding is about — empty for a binary-level
    /// import entry, divergence claim, or COM claim.
    pub fn function(&self) -> &str {
        match self {
            ApiFinding::Import(_) => "",
            ApiFinding::PlatformDivergence(_) => "",
            ApiFinding::ComInterface(_) => "",
            ApiFinding::ApiUsage(record) => &record.function,
        }
    }

    /// The API the finding refers to, spelled for a report row. For a
    /// divergence claim this is the two platform families joined; for
    /// a COM claim it is the recovered interface name, or
    /// `COM runtime` when the claim has no name.
    pub fn target(&self) -> String {
        match self {
            ApiFinding::Import(record) => record.api.clone(),
            ApiFinding::PlatformDivergence(record) => record.families.join(" + "),
            ApiFinding::ComInterface(record) => record
                .interface
                .clone()
                .unwrap_or_else(|| "COM runtime".into()),
            ApiFinding::ApiUsage(record) => record.api.clone(),
        }
    }

    /// The library the API belongs to, when identified. A divergence
    /// claim states families, not one library, and a COM claim states
    /// an interface, not a library, so both return none.
    pub fn library(&self) -> Option<&str> {
        match self {
            ApiFinding::Import(record) => record.library.as_deref(),
            ApiFinding::PlatformDivergence(_) => None,
            ApiFinding::ComInterface(_) => None,
            ApiFinding::ApiUsage(record) => Some(&record.library),
        }
    }

    /// The Rust crate standing in for the API, when identified. A
    /// divergence claim suggests a shape, not a crate, and a COM claim
    /// suggests a trait, not a crate.
    pub fn rust_crate(&self) -> Option<&str> {
        match self {
            ApiFinding::Import(record) => record.rust_crate.as_deref(),
            ApiFinding::PlatformDivergence(_) => None,
            ApiFinding::ComInterface(_) => None,
            ApiFinding::ApiUsage(record) => Some(&record.rust_crate),
        }
    }

    /// The API category the finding's library entry records, spelled
    /// with the PAL `ApiCategory` display names, when the mapping
    /// provides one. A divergence claim states its families through
    /// [`target`](Self::target), not through one category, and a COM
    /// claim names an interface.
    pub fn category(&self) -> Option<&str> {
        match self {
            ApiFinding::Import(record) => record.category.as_deref(),
            ApiFinding::PlatformDivergence(_) => None,
            ApiFinding::ComInterface(_) => None,
            ApiFinding::ApiUsage(record) => record.category.as_deref(),
        }
    }

    /// The feature flags the crate suggestion carries, empty when the
    /// suggestion needs none.
    pub fn features(&self) -> &[String] {
        match self {
            ApiFinding::Import(record) => &record.features,
            ApiFinding::PlatformDivergence(_) => &[],
            ApiFinding::ComInterface(_) => &[],
            ApiFinding::ApiUsage(record) => &record.features,
        }
    }

    /// The crate suggestion, spelled for prompt rows — empty when the
    /// API was never identified. With feature flags the crate renders
    /// in the `crate[feat1, feat2]` form; without them, the bare name.
    /// A divergence claim returns the cfg-gated translation shape
    /// instead. A named COM claim returns the trait shape with the
    /// interface's method listing, and a runtime-level COM claim the
    /// trait shape without names.
    pub fn suggestion(&self) -> String {
        match self {
            ApiFinding::PlatformDivergence(_) => DIVERGENCE_SUGGESTION.to_string(),
            ApiFinding::ComInterface(record) => match &record.interface {
                Some(interface) if !record.methods.is_empty() => format!(
                    "{COM_INTERFACE_SUGGESTION}: trait {interface} with {}",
                    record.methods.join(", ")
                ),
                Some(interface) => format!("{COM_INTERFACE_SUGGESTION}: trait {interface}"),
                None => COM_RUNTIME_SUGGESTION.to_string(),
            },
            _ => match self.rust_crate() {
                None => String::new(),
                Some(krate) if self.features().is_empty() => krate.to_string(),
                Some(krate) => format!("{krate}[{}]", self.features().join(", ")),
            },
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ApiFinding::Import(record) => record.confidence,
            ApiFinding::PlatformDivergence(record) => record.confidence,
            ApiFinding::ComInterface(record) => record.confidence,
            ApiFinding::ApiUsage(record) => record.confidence,
        }
    }

    /// The evidence behind the finding: the call path for a usage, the
    /// API name itself for a binary-level import entry, the triggering
    /// imports from both sides for a divergence claim, the decorated
    /// names (or the COM signals seen) for a COM claim.
    pub fn evidence(&self) -> String {
        match self {
            ApiFinding::Import(record) => record.api.clone(),
            ApiFinding::PlatformDivergence(record) => record.evidence.clone(),
            ApiFinding::ComInterface(record) => record.evidence.clone(),
            ApiFinding::ApiUsage(record) => record.evidence.clone(),
        }
    }

    /// The serde `kind` tag — `import`, `platform_divergence`,
    /// `com_interface`, or `api_usage` — which records which detector
    /// made the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ApiFinding::Import(_) => "import",
            ApiFinding::PlatformDivergence(_) => "platform_divergence",
            ApiFinding::ComInterface(_) => "com_interface",
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
/// of re-scanning. The findings keep a fixed order: the binary-level
/// import entries first, in listing order, then the
/// platform-divergence claim when the imports mix families, then the
/// COM claims when the names show COM signals, then the
/// function-level usages, function by function in call graph order.
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
    /// its usages, and only its usages: a binary-level import entry,
    /// divergence claim, or COM claim belongs to the binary, not to any
    /// function.
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
/// findings). The conversion lives here so the finding's own
/// accessors supply the mapping. An import entry becomes a row with
/// an empty function and `kind = "import"`. A divergence claim
/// becomes a row with an empty function, the joined families as its
/// API, and `kind = "platform_divergence"`. A COM claim becomes a
/// row with an empty function, the interface name (or `COM runtime`)
/// as its API, and `kind = "com_interface"`. A usage keeps its call
/// path and `kind = "direct"` or `"transitive"`.
impl From<&ApiFinding> for calxgloss_prompts::ApiInfo {
    fn from(finding: &ApiFinding) -> Self {
        let kind = match finding {
            ApiFinding::Import(_) => "import",
            ApiFinding::PlatformDivergence(_) => "platform_divergence",
            ApiFinding::ComInterface(_) => "com_interface",
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
            api: finding.target(),
            library: finding.library().unwrap_or("").to_string(),
            suggestion: finding.suggestion(),
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
            category: Some("zlib".into()),
            features: vec!["zlib".into()],
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
            category: Some("Win32Core".into()),
            features: Vec::new(),
            confidence: Confidence::new(90),
        });
        assert_eq!(finding.function(), "");
        assert_eq!(finding.target(), "CreateFileA");
        assert_eq!(finding.library(), Some("Win32"));
        assert_eq!(finding.rust_crate(), Some("windows / std::fs"));
        assert_eq!(finding.category(), Some("Win32Core"));
        assert!(finding.features().is_empty());
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
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(0),
        });
        assert_eq!(finding.library(), None);
        assert_eq!(finding.rust_crate(), None);
        assert_eq!(finding.category(), None);
        assert!(finding.features().is_empty());
    }

    #[test]
    fn usage_finding_reads_through_the_union_accessors() {
        let finding = ApiFinding::ApiUsage(usage());
        assert_eq!(finding.function(), "FUN_18003ab00");
        assert_eq!(finding.target(), "inflate");
        assert_eq!(finding.library(), Some("zlib"));
        assert_eq!(finding.rust_crate(), Some("flate2"));
        assert_eq!(finding.category(), Some("zlib"));
        assert_eq!(finding.features(), ["zlib".to_string()]);
        assert_eq!(finding.confidence(), Confidence::new(60));
        assert_eq!(
            finding.evidence(),
            "FUN_18003ab00 → FUN_18003c000 → inflate"
        );
        assert_eq!(finding.kind(), "api_usage");
    }

    #[test]
    fn the_suggestion_accessor_renders_the_bare_crate_without_features() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "CreateFileA".into(),
            library: Some("Win32".into()),
            rust_crate: Some("windows / std::fs".into()),
            category: Some("Win32Core".into()),
            features: Vec::new(),
            confidence: Confidence::new(90),
        });
        assert_eq!(finding.suggestion(), "windows / std::fs");

        let unidentified = ApiFinding::Import(ApiSignature {
            api: "VendorSpecialFunction".into(),
            library: None,
            rust_crate: None,
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(0),
        });
        assert_eq!(unidentified.suggestion(), "");
    }

    #[test]
    fn the_suggestion_accessor_renders_the_crate_feature_form_with_features() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "inflate".into(),
            library: Some("zlib".into()),
            rust_crate: Some("flate2".into()),
            category: Some("zlib".into()),
            features: vec!["zlib".into()],
            confidence: Confidence::new(90),
        });
        assert_eq!(finding.suggestion(), "flate2[zlib]");

        let usage = ApiFinding::ApiUsage(ApiUsage {
            features: vec!["png".into(), "color_quant".into()],
            ..usage()
        });
        assert_eq!(usage.suggestion(), "flate2[png, color_quant]");
    }

    #[test]
    fn findings_round_trip_through_serde_with_the_kind_tag() {
        let findings = vec![
            ApiFinding::Import(ApiSignature {
                api: "inflate".into(),
                library: Some("zlib".into()),
                rust_crate: Some("flate2".into()),
                category: Some("zlib".into()),
                features: vec!["zlib".into()],
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

    fn divergence() -> PlatformDivergence {
        PlatformDivergence {
            families: vec!["Win32Core".into(), "POSIX".into()],
            evidence: "CreateFileA (Win32Core), fopen (POSIX)".into(),
            confidence: Confidence::new(70),
        }
    }

    #[test]
    fn divergence_finding_reads_through_the_union_accessors() {
        let finding = ApiFinding::PlatformDivergence(divergence());
        assert_eq!(finding.function(), "", "the claim is binary-level");
        assert_eq!(finding.target(), "Win32Core + POSIX", "both families named");
        assert_eq!(finding.library(), None);
        assert_eq!(finding.rust_crate(), None);
        assert_eq!(finding.category(), None);
        assert!(finding.features().is_empty());
        assert_eq!(finding.confidence(), Confidence::new(70));
        assert_eq!(finding.evidence(), "CreateFileA (Win32Core), fopen (POSIX)");
        assert_eq!(finding.kind(), "platform_divergence");
        assert!(
            finding.suggestion().contains("cfg"),
            "the suggestion names the cfg-gated shape, not a crate: {}",
            finding.suggestion()
        );
    }

    #[test]
    fn divergence_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ApiFinding::PlatformDivergence(divergence());
        let json = serde_json::to_string(&finding).unwrap();
        let back: ApiFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
        assert!(json.contains(r#""kind":"platform_divergence""#));
    }

    #[test]
    fn divergence_finding_converts_to_a_prompt_row() {
        let info = calxgloss_prompts::ApiInfo::from(&ApiFinding::PlatformDivergence(divergence()));
        assert_eq!(info.function, "");
        assert_eq!(info.api, "Win32Core + POSIX");
        assert_eq!(info.library, "");
        assert!(info.suggestion.contains("cfg"));
        assert_eq!(info.kind, "platform_divergence");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.evidence, "CreateFileA (Win32Core), fopen (POSIX)");
    }

    fn com() -> ComInterface {
        ComInterface {
            interface: Some("IDataSource".into()),
            methods: vec!["QueryInterface".into(), "AddRef".into(), "Release".into()],
            evidence:
                "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z, ?Release@IDataSource@@UEAAKXZ"
                    .into(),
            confidence: Confidence::new(70),
        }
    }

    #[test]
    fn com_finding_reads_through_the_union_accessors() {
        let finding = ApiFinding::ComInterface(com());
        assert_eq!(finding.function(), "", "the claim is binary-level");
        assert_eq!(finding.target(), "IDataSource", "the interface is named");
        assert_eq!(finding.library(), None);
        assert_eq!(finding.rust_crate(), None);
        assert_eq!(finding.category(), None);
        assert!(finding.features().is_empty());
        assert_eq!(finding.confidence(), Confidence::new(70));
        assert_eq!(
            finding.evidence(),
            "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z, ?Release@IDataSource@@UEAAKXZ"
        );
        assert_eq!(finding.kind(), "com_interface");
        let suggestion = finding.suggestion();
        assert!(suggestion.contains("trait"), "got: {suggestion}");
        assert!(
            suggestion.contains("QueryInterface, AddRef, Release"),
            "the method listing is included in the suggestion: {suggestion}"
        );
    }

    #[test]
    fn a_runtime_level_com_finding_reads_through_the_union_accessors() {
        // No interface name recovered: the claim names the COM runtime,
        // carries no methods, and sits visibly below a named claim.
        let finding = ApiFinding::ComInterface(ComInterface {
            interface: None,
            methods: Vec::new(),
            evidence: "CoCreateInstance, CoTaskMemAlloc".into(),
            confidence: Confidence::new(50),
        });
        assert_eq!(finding.function(), "");
        assert_eq!(finding.target(), "COM runtime");
        assert_eq!(finding.kind(), "com_interface");
        assert_eq!(finding.confidence(), Confidence::new(50));
        assert!(
            finding.confidence() < Confidence::new(70),
            "a nameless claim sits below a named-interface claim"
        );
        assert!(
            finding.suggestion().contains("trait"),
            "the runtime claim still suggests the trait shape: {}",
            finding.suggestion()
        );
    }

    #[test]
    fn com_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ApiFinding::ComInterface(com());
        let json = serde_json::to_string(&finding).unwrap();
        let back: ApiFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
        assert!(json.contains(r#""kind":"com_interface""#));
    }

    #[test]
    fn a_runtime_level_com_finding_serde_round_trips_without_the_nameless_fields() {
        let finding = ApiFinding::ComInterface(ComInterface {
            interface: None,
            methods: Vec::new(),
            evidence: "CoCreateInstance".into(),
            confidence: Confidence::new(50),
        });
        let json = serde_json::to_string(&finding).unwrap();
        let back: ApiFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
        assert!(!json.contains("\"interface\""), "got: {json}");
        assert!(!json.contains("\"methods\""), "got: {json}");
    }

    #[test]
    fn com_finding_converts_to_a_prompt_row() {
        let info = calxgloss_prompts::ApiInfo::from(&ApiFinding::ComInterface(com()));
        assert_eq!(info.function, "");
        assert_eq!(info.api, "IDataSource");
        assert_eq!(info.library, "");
        assert!(info.suggestion.contains("trait"));
        assert_eq!(info.kind, "com_interface");
        assert_eq!(info.confidence, 70);
        assert!(info.evidence.contains("?QueryInterface@IDataSource@@"));
    }

    #[test]
    fn import_finding_converts_to_a_prompt_row() {
        let finding = ApiFinding::Import(ApiSignature {
            api: "inflate".into(),
            library: Some("zlib".into()),
            rust_crate: Some("flate2".into()),
            category: Some("zlib".into()),
            features: vec!["zlib".into()],
            confidence: Confidence::new(90),
        });
        let info = calxgloss_prompts::ApiInfo::from(&finding);
        assert_eq!(info.function, "");
        assert_eq!(info.api, "inflate");
        assert_eq!(info.library, "zlib");
        assert_eq!(info.suggestion, "flate2[zlib]");
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
