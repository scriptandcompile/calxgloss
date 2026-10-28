//! String-context scan orchestration.
//!
//! [`StringContextEngine`] runs the parts of this crate over one open
//! program: the string classifier, the hybrid string-to-function
//! mapper, [`FormatStringEngine`], [`LocalizationDetector`], and
//! [`CrossFunctionAnalyzer`]. The cross-function pass runs after the
//! per-function pass, over the kept bodies. Their findings are combined
//! into one [`StringContextResult`] with its scan provenance.
//!
//! The scan walks the function listing once, in order. It makes one
//! `strings()` call up front and one decompile per function. It makes
//! xref lookups only where a function's body parse found nothing; that
//! hybrid rule keeps a scan cheap. Each program string is classified
//! once, and every function that uses it reads the same answer. Xref
//! responses are cached per string address, so the fallback never asks
//! the same question twice.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use calxgloss_decomp::{DecompiledFunction, Xref};
use calxgloss_kuna::KunaSource;
use tracing::{info, warn};

use crate::classify::StringClassifyEngine;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::format_str::FormatStringEngine;
use crate::hybrid_mapper::{BODY_CONFIDENCE, HybridXrefMapper, XREF_CONFIDENCE};
use crate::localization::{LocalizationDetector, MappedStringSignal};
use crate::types::{
    ClassifiedString, Confidence, FormatStringUse, ScanMetadata, StringClassification,
    StringContextResult, StringFinding, StringSource,
};
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};

/// The program a string-context scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the scan's generic type parameter names it directly.
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned listings, bodies, strings, and
/// xrefs, so the orchestration runs without a server. The futures are
/// `Send`, so a task can drive a scan from another thread.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names by
/// name before it reports the rest as a count. This keeps the admission
/// a short sentence beside the counts, rather than a long list dump
/// (the P19-7 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a string-context scan declares, in order. The record must
/// name each one exactly once: the decompiled bodies, the program-wide
/// string listing, and the cross-reference lookups the fallback makes.
pub const DECLARED_FACETS: &[&str] = &["function-bodies", "program-strings", "string-xrefs"];

/// The coverage record every string-context scan writes about itself
/// (issue #351), beside the provenance and the timing.
///
/// The string-context scan reads three facets.
///
/// `function-bodies` covers the decompiled bodies the body parse reads.
/// The scan always reads the function listing end to end: a failed
/// listing aborts the scan, and more than half of the listing failing
/// to decompile trips the skip-rate breaker. So in a finished scan, the
/// bodies it cannot have read are exactly the ones it skipped: a
/// nameless listing entry, or a decompile that failed.
///
/// `program-strings` covers the program-wide string listing, which the
/// `DAT_` resolution and the xref fallback need. A failed listing costs
/// the scan that evidence and nothing else, so the facet is then
/// `unavailable` with its reason, rather than silently empty.
///
/// `string-xrefs` covers the cross-reference lookups the fallback makes
/// for each program string when a body came up empty. If every lookup
/// fails, the facet is `unavailable`: no cross-reference could be read.
/// If some lookups land, it is `partial`, and it counts the ones that
/// never answered.
///
/// When nothing is skipped and every read is answered, the facets are
/// `complete`. That is the point of the admission: a string no finding
/// maps was examined and clean, never silently unchecked.
///
/// The cross-function pass reads the bodies and the string table the
/// scan already holds, so it adds no coverage boundary of its own. The
/// whole picture follows the three facets together.
fn coverage_stamp(
    unreached: &[String],
    nameless: usize,
    strings_unreadable: bool,
    xrefs_read: usize,
    xrefs_unreadable: usize,
) -> ScanCoverage {
    let bodies = {
        let total = unreached.len() + nameless;
        if total == 0 {
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }
        } else {
            let mut names = unreached
                .iter()
                .take(MAX_NAMED_UNREACHED)
                .cloned()
                .collect::<Vec<_>>();
            let hidden = unreached.len().saturating_sub(names.len()) + nameless;
            if hidden > 0 {
                names.push(format!("+{hidden} more"));
            }
            let body = if total == 1 { "body" } else { "bodies" };
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Partial,
                limitation: Some(format!(
                    "{total} function {body} unreached: {}",
                    names.join(", ")
                )),
            }
        }
    };
    let strings = if strings_unreadable {
        FacetCoverage {
            id: "program-strings".to_string(),
            status: CoverageStatus::Unavailable,
            limitation: Some("program string listing unreadable".to_string()),
        }
    } else {
        FacetCoverage {
            id: "program-strings".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    };
    let xrefs = if xrefs_unreadable == 0 {
        FacetCoverage {
            id: "string-xrefs".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else if xrefs_read == 0 {
        FacetCoverage {
            id: "string-xrefs".to_string(),
            status: CoverageStatus::Unavailable,
            limitation: Some("no string cross-reference could be read".to_string()),
        }
    } else {
        let lookup = if xrefs_unreadable == 1 {
            "lookup"
        } else {
            "lookups"
        };
        FacetCoverage {
            id: "string-xrefs".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{xrefs_unreadable} string cross-reference {lookup} unreadable"
            )),
        }
    };
    let status = if bodies.status == CoverageStatus::Complete
        && strings.status == CoverageStatus::Complete
        && xrefs.status == CoverageStatus::Complete
    {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    ScanCoverage {
        status,
        facets: vec![bodies, strings, xrefs],
    }
}

/// Runs the classifier, the hybrid mapper, [`FormatStringEngine`],
/// [`LocalizationDetector`], and [`CrossFunctionAnalyzer`] together and
/// combines them into one [`StringContextResult`].
///
/// This type is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned program data.
/// [`new`](Self::new) builds one over a loaded [`KunaSource`]. None of
/// the parts keep state for one scan:
/// [`with_classifier`](Self::with_classifier),
/// [`with_mapper`](Self::with_mapper),
/// [`with_format_engine`](Self::with_format_engine), and
/// [`with_localization`](Self::with_localization) each replace one part
/// whole. So one of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct StringContextEngine<S = KunaSource> {
    source: S,
    classifier: StringClassifyEngine,
    mapper: HybridXrefMapper,
    format_engine: FormatStringEngine,
    localization: LocalizationDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl StringContextEngine<KunaSource> {
    /// A string-context scan over a loaded Kuna program, using the
    /// classifier's standard pattern sets.
    pub fn new(source: &KunaSource) -> StringContextEngine<KunaSource> {
        StringContextEngine {
            source: source.clone(),
            classifier: StringClassifyEngine::with_default_patterns(),
            mapper: HybridXrefMapper::new(),
            format_engine: FormatStringEngine::new(),
            localization: LocalizationDetector::new(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> StringContextEngine<S> {
    /// A string-context scan whose program data comes from `source`,
    /// using the classifier's standard pattern sets.
    pub fn with_source(source: S) -> Self {
        StringContextEngine {
            source,
            classifier: StringClassifyEngine::with_default_patterns(),
            mapper: HybridXrefMapper::new(),
            format_engine: FormatStringEngine::new(),
            localization: LocalizationDetector::new(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Classify against `classifier`'s pattern sets instead of the
    /// standard ones.
    pub fn with_classifier(mut self, classifier: StringClassifyEngine) -> Self {
        self.classifier = classifier;
        self
    }

    /// Map strings to functions with `mapper`'s format-function list
    /// instead of the standard one.
    pub fn with_mapper(mut self, mapper: HybridXrefMapper) -> Self {
        self.mapper = mapper;
        self
    }

    /// Read format strings through `format_engine` instead of the
    /// standard specifier table.
    pub fn with_format_engine(mut self, format_engine: FormatStringEngine) -> Self {
        self.format_engine = format_engine;
        self
    }

    /// Read localization signals through `localization`'s language-name
    /// set instead of the standard one.
    pub fn with_localization(mut self, localization: LocalizationDetector) -> Self {
        self.localization = localization;
        self
    }

    /// Map the program's strings to its functions, over the whole
    /// program named by `binary`. Each function is decompiled exactly
    /// once. Xrefs are consulted only where a body parse came up empty.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under.
    ///
    /// The findings follow the function listing, function by function.
    /// Within one function come the classified strings, then the
    /// format-string calls, then the localization reading. After every
    /// function the cross-function pass adds its string-flow findings,
    /// in listing order, over the bodies this pass already decompiled.
    /// It makes no extra reads from the analysis engine. So two scans of
    /// the same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning, and so is a nameless
    /// listing entry. A failed xref lookup costs only that string's
    /// fallback coverage. A failed string listing costs only the
    /// fallback and `DAT_` resolution. Only a failure of the function
    /// listing itself — the server being down — aborts the scan, because
    /// then there is nothing to read.
    /// When more than half of the program's functions fail to decompile,
    /// the skip-rate breaker aborts the scan too. A high skip rate is
    /// the signature of the seam answering about the wrong program. The
    /// breaker is a fuse, not a post-mortem: it stops the scan rather
    /// than let it persist a record that looks clean but is not
    /// (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<StringContextResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        // Only a failed function listing is fatal. A failed string
        // listing costs the fallback and `DAT_` resolution, but the
        // body parse still reads its direct literals. So the scan logs a
        // warning instead of aborting, and the coverage record below
        // admits the listing as unreadable (issue #351).
        let mut strings_unreadable = false;
        let program_strings = match self.source.strings().await {
            Ok(strings) => strings,
            Err(error) => {
                warn!(
                    error = %error,
                    "String listing failed; scanning body literals only"
                );
                strings_unreadable = true;
                Vec::new()
            }
        };
        let string_table: HashMap<u64, String> = program_strings
            .iter()
            .map(|string| (string.address, string.value.clone()))
            .collect();
        // The decoded string values from the program's string listing.
        // Only these can carry the localization detector's non-ASCII
        // signal, so an escaped body literal can neither fake one nor
        // hide one.
        let listing_values: HashSet<&str> = program_strings
            .iter()
            .map(|string| string.value.as_str())
            .collect();

        // Classification is a property of the string, not of the
        // function that uses it. The scan classifies each program string
        // once, and every function that touches it reads the same
        // answer.
        let mut classifications: HashMap<String, (StringClassification, &'static str)> =
            HashMap::new();
        // The fallback asks each string address at most once per scan.
        let mut xref_cache: HashMap<u64, Vec<Xref>> = HashMap::new();
        // Addresses whose lookup was attempted and never answered, so
        // the coverage record below can count them (issue #351). An
        // address that answers on a later try is not counted.
        let mut xref_unreadable: HashSet<u64> = HashSet::new();

        let mut findings = Vec::new();
        // The kept bodies: the ones this pass decompiled successfully,
        // held in listing order for the cross-function pass. Nothing is
        // decompiled twice.
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // The functions this pass never reached, recorded by name as the
        // scan goes, so the coverage record below can admit them
        // (issue #351).
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A listing entry with no name would make the decompile
                // lookup land on some other function's body. Nothing can
                // be said about such an entry, so the scan records
                // nothing for it.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
                continue;
            }
            let decompiled = match self.source.decompile(&function.name).await {
                Ok(decompiled) => decompiled,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping function: decompile failed"
                    );
                    skipped += 1;
                    decompile_failures += 1;
                    unreached.push(function.name.clone());
                    // Skip-rate breaker: more than half of the
                    // program's functions have failed to decompile. A
                    // high skip rate is the signature of the seam
                    // answering about the wrong program. The breaker is
                    // a fuse, not a post-mortem: it aborts with the
                    // counts, instead of letting the scan persist a
                    // record that looks clean but is not.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::StringCtxError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            let body_usages = self.mapper.extract_strings_from_body(
                &function.name,
                &decompiled.body,
                &string_table,
            );
            let format_calls =
                self.mapper
                    .extract_format_calls(&function.name, &decompiled.body, &string_table);
            // Where this function's findings begin, so the localization
            // reading can look at the classified records just made.
            let function_findings_start = findings.len();

            // The hybrid rule: if the body parse found strings, this
            // function gets no xref lookups. Only a function whose body
            // came up empty is covered through the xref fallback.
            let usages = if body_usages.is_empty() && format_calls.is_empty() {
                let mut fallback = Vec::new();
                for string in &program_strings {
                    let xrefs = match xref_cache.get(&string.address) {
                        Some(xrefs) => xrefs.clone(),
                        None => match self.source.xrefs_to(string.address).await {
                            Ok(xrefs) => {
                                xref_cache.insert(string.address, xrefs.clone());
                                xrefs
                            }
                            Err(error) => {
                                warn!(
                                    address = format_args!("{:#x}", string.address),
                                    error = %error,
                                    "Skipping string in xref fallback: lookup failed"
                                );
                                xref_unreadable.insert(string.address);
                                continue;
                            }
                        },
                    };
                    fallback.extend(
                        self.mapper
                            .extract_strings_from_xrefs(string, &xrefs)
                            .into_iter()
                            .filter(|usage| usage.function == function.name),
                    );
                }
                // Two references from one function to one string — two
                // call sites, say — still record once.
                HybridXrefMapper::merge_usages(Vec::new(), fallback)
            } else {
                body_usages
            };

            // A string read as a format string is recorded through its
            // format call, and not also as a plain classified string.
            let format_keys: HashSet<(u64, String)> = format_calls
                .iter()
                .map(|call| (call.string_address, call.format_string.clone()))
                .collect();

            for usage in usages {
                if format_keys.contains(&(usage.string_address, usage.string_value.clone())) {
                    continue;
                }
                let (classification, purpose) = *classifications
                    .entry(usage.string_value.clone())
                    .or_insert_with(|| {
                        let classification = self.classifier.classify(&usage.string_value);
                        (
                            classification,
                            self.classifier.infer_purpose(classification),
                        )
                    });
                let confidence = match usage.source {
                    StringSource::BodyParse => BODY_CONFIDENCE,
                    StringSource::Xref => XREF_CONFIDENCE,
                };
                findings.push(StringFinding::Classified(ClassifiedString {
                    function: usage.function,
                    string_address: usage.string_address,
                    string_value: usage.string_value,
                    classification,
                    purpose: purpose.to_string(),
                    source: usage.source,
                    confidence: Confidence::new(confidence),
                    evidence: usage.evidence,
                }));
            }
            for call in format_calls {
                let arg_types = self.format_engine.extract_hints(&call.format_string);
                findings.push(StringFinding::FormatString(FormatStringUse {
                    function: call.function,
                    format_string: call.format_string,
                    string_address: call.string_address,
                    call_site: call.call_site,
                    arg_types,
                    confidence: Confidence::new(BODY_CONFIDENCE),
                }));
            }

            // The localization reading comes after the format-string
            // reading within one function. It reads the string values
            // the scan just mapped and classified for this function, so
            // it makes no new ScanSource reads. It adds at most one
            // finding, beside the classified records, and never
            // reclassifies them.
            let candidates: Vec<MappedStringSignal<'_>> = findings[function_findings_start..]
                .iter()
                .filter_map(|finding| match finding {
                    StringFinding::Classified(record) => Some(MappedStringSignal {
                        value: &record.string_value,
                        classification: record.classification,
                        from_listing: listing_values.contains(record.string_value.as_str()),
                        evidence: &record.evidence,
                    }),
                    _ => None,
                })
                .collect();
            if let Some(signals) = self.localization.detect(&function.name, &candidates) {
                findings.push(StringFinding::Localization(signals));
            }
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function pass. It
        // reads only the bodies the scan already decompiled and the
        // string table it already holds, so it makes no new `ScanSource`
        // reads. That keeps the exactly-once-decompile contract and the
        // skip-rate breaker untouched. Its findings are appended after
        // the per-function findings, in listing order. A function whose
        // decompile failed contributed no body, so it passes nothing,
        // receives nothing, and binds no edge.
        findings.extend(
            self.cross_function
                .analyze(&bodies, &string_table, &self.mapper)
                .into_iter()
                .map(StringFinding::CrossFunction),
        );

        let mut metadata = ScanMetadata::new(binary);
        // The scan writes its own coverage admission where the skips and
        // the unreadable reads happened, so the filed record says what
        // this pass never reached (issue #351). A complete record lets
        // any string it does not mention read as examined and clean. An
        // address that answered on a later try counts as read.
        metadata.coverage = Some(coverage_stamp(
            &unreached,
            nameless,
            strings_unreadable,
            xref_cache.len(),
            xref_unreadable
                .iter()
                .filter(|address| !xref_cache.contains_key(*address))
                .count(),
        ));
        // The source names the analysis engine and its version pin,
        // filed under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            strings = program_strings.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Mapped program strings to functions"
        );
        Ok(StringContextResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::CategoryPatterns;
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn summary(name: &str) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address: 0x1800_3ab00,
        }
    }

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("\nundefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    /// A canned program that implements [`ScanSource`]. It counts each
    /// fetch and can fail each read on purpose, so these tests watch the
    /// orchestration and break it without a server.
    #[derive(Clone, Default)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        literals: Vec<StringLiteral>,
        xrefs: HashMap<u64, Vec<Xref>>,
        fail_listing: bool,
        fail_strings: bool,
        fail_decompile: Vec<String>,
        fail_xrefs: bool,
        fail_xref_addrs: Vec<u64>,
        decompile_fetches: Arc<AtomicUsize>,
        xref_fetches: Arc<AtomicUsize>,
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.decompile_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_decompile.iter().any(|f| f == name) {
                return Err(EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            if self.fail_strings {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.literals.clone())
        }

        async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
            self.xref_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_xrefs || self.fail_xref_addrs.contains(&address) {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
        }

        // The rest of the shared trait's reads. The string-context scan
        // never makes these calls, so they return empty or not-found
        // data.
        async fn callers(&self, _address: u64) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
            Err(EngineError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(EngineError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> Result<u64> {
            Ok(0)
        }

        async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn program() -> FakeProgram {
        let mut program = FakeProgram {
            listing: vec![summary("FUN_18003ab00"), summary("FUN_18003e750")],
            ..FakeProgram::default()
        };
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "  lFile = CreateFileA(\"Journal.txt\",0xc0000000,0,0,3,0x80,0);\n\
                 \x20 puVar3 = (uint *)DAT_180128cf0;\n\
                 \x20 sprintf(local_10, \"%s: %d hits\", pcVar2, uVar3);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "  return;\n"),
        );
        program.literals = vec![
            StringLiteral {
                address: 0x180128cf0,
                value: "********** Chat logging turned OFF.".to_string(),
            },
            StringLiteral {
                address: 0x180129a00,
                value: "%s: %d hits".to_string(),
            },
        ];
        program.xrefs.insert(
            0x180128cf0,
            vec![Xref {
                address: 0x180006f04,
                function: Some("FUN_18003e750".to_string()),
                kind: Some("DATA".to_string()),
            }],
        );
        program
    }

    #[tokio::test]
    async fn a_scan_maps_body_strings_and_format_calls_in_scan_order() {
        let result = StringContextEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        // FUN_18003ab00: the direct literal and the DAT_ reference both
        // classify, and the sprintf call reads as a format_string
        // finding. The format string is not also recorded as a
        // classified string.
        let ab00: Vec<&StringFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(ab00.len(), 3);
        assert_eq!(ab00[0].kind(), "classified");
        assert_eq!(ab00[0].target(), "Journal.txt");
        assert_eq!(ab00[1].kind(), "classified");
        assert_eq!(ab00[1].target(), "********** Chat logging turned OFF.");
        assert_eq!(ab00[2].kind(), "format_string");
        assert_eq!(ab00[2].target(), "%s: %d hits");

        // FUN_18003e750 has no strings in its body, but the chat-logging
        // string points back to it through an xref, so the fallback
        // covers it.
        let e750: Vec<&StringFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(e750.len(), 1);
        assert_eq!(e750[0].target(), "********** Chat logging turned OFF.");
    }

    #[tokio::test]
    async fn the_xref_fallback_runs_only_for_functions_whose_body_found_no_strings() {
        let program = program();
        let result = StringContextEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        // FUN_18003ab00's body carried strings, so its evidence is all
        // body-parsed; FUN_18003e750's came from the fallback.
        for finding in result.for_function("FUN_18003ab00") {
            if let StringFinding::Classified(record) = finding {
                assert_eq!(record.source, StringSource::BodyParse);
            }
        }
        for finding in result.for_function("FUN_18003e750") {
            if let StringFinding::Classified(record) = finding {
                assert_eq!(record.source, StringSource::Xref);
            }
        }

        // Each string address is asked once per scan, not once per
        // fallback function.
        assert_eq!(program.xref_fetches.load(Ordering::SeqCst), 2);
        // And one decompile per function.
        assert_eq!(program.decompile_fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn confidence_follows_the_provenance() {
        let result = StringContextEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        for finding in result.for_function("FUN_18003ab00") {
            assert_eq!(finding.confidence(), Confidence::new(70));
        }
        for finding in result.for_function("FUN_18003e750") {
            assert_eq!(finding.confidence(), Confidence::new(60));
        }
    }

    #[tokio::test]
    async fn a_function_whose_body_cannot_be_fetched_is_skipped_not_fatal() {
        let mut program = program();
        program.fail_decompile = vec!["FUN_18003ab00".to_string()];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(result.for_function("FUN_18003ab00").next().is_none());
        assert!(result.for_function("FUN_18003e750").next().is_some());
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The 2026-10-08 incident: the seam answered the listing from
        // one program and the decompiles from another. Every decompile
        // failed, and the scan nearly persisted a record that looked
        // clean but was not, under the target's name. The skip-rate
        // breaker aborts with the counts instead, so nothing is saved.
        let mut program = program();
        program.fail_decompile = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::StringCtxError::DecompileBreaker {
                failed: 2,
                total: 2
            })
        ));
    }

    #[tokio::test]
    async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
        // The skip-rate breaker is a fuse, not a post-mortem. Once more
        // than half the listing has failed, the remaining decompiles are
        // wasted requests about the wrong program.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function("FUN_1800412a0", "  return;\n"),
        );
        program.fail_decompile = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = StringContextEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::StringCtxError::DecompileBreaker {
                failed: 2,
                total: 3
            })
        ));
        assert_eq!(
            program.decompile_fetches.load(Ordering::SeqCst),
            2,
            "the scan stopped once the breaker tripped"
        );
    }

    #[tokio::test]
    async fn a_nameless_listing_entry_is_skipped() {
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(result.for_function("").next().is_none());
    }

    #[tokio::test]
    async fn a_failed_function_listing_aborts_the_scan() {
        let mut program = program();
        program.fail_listing = true;
        assert!(
            StringContextEngine::with_source(program)
                .scan("eqmain.dll")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_failed_string_listing_degrades_to_body_literals_only() {
        // Only the function listing is fatal: with no string table the
        // body parse still reads its direct literals, and the fallback
        // and `DAT_` resolution simply find nothing.
        let mut program = program();
        program.fail_strings = true;
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("the scan survives a failed string listing");

        let ab00: Vec<&StringFinding> = result.for_function("FUN_18003ab00").collect();
        assert!(
            ab00.iter().any(|finding| finding.target() == "Journal.txt"),
            "the body's direct literal is still recorded"
        );
        assert!(
            !ab00
                .iter()
                .any(|finding| finding.target() == "********** Chat logging turned OFF."),
            "the unresolvable DAT_ reference is not"
        );
        assert_eq!(
            result.for_function("FUN_18003e750").count(),
            0,
            "the fallback has no strings to ask about"
        );
    }

    #[tokio::test]
    async fn two_xrefs_to_one_string_from_one_function_record_once() {
        // Two call sites, one string: the fallback keeps one record per
        // address and value, so the function carries a single record.
        let mut program = program();
        program
            .xrefs
            .get_mut(&0x180128cf0)
            .expect("the fixture string has an xref")
            .push(Xref {
                address: 0x1800_7a20,
                function: Some("FUN_18003e750".to_string()),
                kind: Some("DATA".to_string()),
            });
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let e750: Vec<&StringFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(e750.len(), 1, "one record for the two references");
        assert_eq!(e750[0].target(), "********** Chat logging turned OFF.");
    }

    #[tokio::test]
    async fn a_failed_xref_lookup_costs_only_that_string_s_fallback_coverage() {
        let mut program = program();
        program.fail_xrefs = true;
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        // The body-parsed findings stand; the fallback function just
        // comes up empty.
        assert!(result.for_function("FUN_18003ab00").next().is_some());
        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn the_sub_engine_setters_reach_the_scan() {
        // A fixture classifier that calls everything a network address.
        let classifier = StringClassifyEngine::with_patterns(CategoryPatterns {
            network: vec!["(?i).*".to_string()],
            ..CategoryPatterns::default()
        });
        let result = StringContextEngine::with_source(program())
            .with_classifier(classifier)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let StringFinding::Classified(record) =
            result.for_function("FUN_18003ab00").next().unwrap()
        else {
            unreachable!("the first finding is a classified string");
        };
        assert_eq!(record.classification, StringClassification::Network);
    }

    #[tokio::test]
    async fn the_scan_stamps_provenance_into_metadata() {
        let result = StringContextEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
    }

    /// The shared fixture plus a language-selection function: `English`
    /// and `en-US` references, a user-visible listing value carrying an
    /// accented character, a language word buried in a sentence, an
    /// escaped body literal, and a `sprintf` call.
    fn localization_program() -> FakeProgram {
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "  pcVar1 = (char *)DAT_180129b00;\n\
                 \x20 pcVar2 = (char *)DAT_180129b10;\n\
                 \x20 pcVar3 = (char *)DAT_180129b20;\n\
                 \x20 pcVar4 = (char *)DAT_180129b30;\n\
                 \x20 pcVar5 = \"caf\\xe9\";\n\
                 \x20 sprintf(local_10, \"%s: %d hits\", pcVar1, iVar2);\n",
            ),
        );
        program.literals.extend(
            [
                (0x180129b00, "English"),
                (0x180129b10, "en-US"),
                (0x180129b20, "Welcome to the Café"),
                (0x180129b30, "Do you speak English?"),
            ]
            .map(|(address, value)| StringLiteral {
                address,
                value: value.to_string(),
            }),
        );
        program
    }

    #[tokio::test]
    async fn localization_signals_land_one_finding_after_the_format_string_reading() {
        let program = localization_program();
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        // The scan order, extended: within one function come the
        // classified strings, then the format-string call, then the
        // localization reading. The escaped literal and the buried
        // language word stay classified records and claim no signal.
        let findings: Vec<&StringFinding> = result.for_function("FUN_1800412a0").collect();
        let kinds: Vec<&str> = findings.iter().map(|finding| finding.kind()).collect();
        assert_eq!(
            kinds,
            [
                "classified",
                "classified",
                "classified",
                "classified",
                "classified",
                "format_string",
                "localization",
            ]
        );

        // The function gets one finding, naming every signal kind seen
        // and the signal strings themselves. The buried language word and
        // the escaped body literal claim nothing.
        let StringFinding::Localization(record) = findings.last().unwrap() else {
            unreachable!("the language machinery reads as a localization finding");
        };
        assert_eq!(
            record.signal_kinds,
            [
                crate::types::LocalizationSignalKind::LanguageName,
                crate::types::LocalizationSignalKind::LocaleCode,
                crate::types::LocalizationSignalKind::NonAsciiText,
            ]
        );
        assert_eq!(record.signals, ["English", "en-US", "Welcome to the Café"]);
        assert_eq!(
            record.evidence,
            "pcVar1 = (char *)DAT_180129b00; pcVar2 = (char *)DAT_180129b10; \
             pcVar3 = (char *)DAT_180129b20;"
        );
        // This pattern-based reading scores visibly below a classified
        // record.
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(
            findings.last().unwrap().suggestion(),
            "model the language switch as a Rust enum with the localized strings held in a table"
        );
        assert_eq!(
            findings.last().unwrap().target(),
            "English, en-US, Welcome to the Café"
        );

        // The classified records stand unchanged beside the reading.
        assert_eq!(findings[0].target(), "English");
        assert_eq!(findings[2].target(), "Welcome to the Café");
        assert!(
            findings[..5]
                .iter()
                .any(|finding| finding.target() == "caf\\xe9"),
            "the escaped literal is still a classified record — just no signal"
        );

        // A function with no signals reports nothing.
        assert!(
            result
                .for_function("FUN_18003ab00")
                .all(|finding| finding.kind() != "localization")
        );
        assert!(
            result
                .for_function("FUN_18003e750")
                .all(|finding| finding.kind() != "localization")
        );
    }

    #[tokio::test]
    async fn the_localization_setter_reaches_the_scan() {
        // A language name this binary uses. `with_localization` makes the
        // scan read it, in the same way as the other part setters.
        let mut program = localization_program();
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "  pcVar1 = \"Klingon\";\n"),
        );

        // The default set claims nothing for "Klingon".
        let result = StringContextEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            result
                .for_function("FUN_18003e750")
                .all(|finding| finding.kind() != "localization")
        );

        // The configured set reaches the scan.
        let result = StringContextEngine::with_source(program)
            .with_localization(LocalizationDetector::with_names(["Klingon"]))
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let findings: Vec<&StringFinding> = result.for_function("FUN_18003e750").collect();
        let StringFinding::Localization(record) = findings.last().unwrap() else {
            unreachable!("the configured name reads as a localization signal");
        };
        assert_eq!(record.signals, ["Klingon"]);
    }

    /// The shared fixture plus strings handed across call boundaries:
    /// `FUN_18003ab00` passes a direct literal (twice) and a resolved
    /// `DAT_` string into `FUN_18003e750`, and `FUN_1800412a0` — later
    /// in the listing — hands one back to `FUN_18003e750`. The
    /// `CreateFileA` import call and the `pcVar2` variable argument
    /// claim no flow.
    fn correlation_program() -> FakeProgram {
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "  lFile = CreateFileA(\"Journal.txt\",0xc0000000,0,0,3,0x80,0);\n\
                 \x20 puVar3 = (uint *)DAT_180128cf0;\n\
                 \x20 sprintf(local_10, \"%s: %d hits\", pcVar2, uVar3);\n\
                 \x20 FUN_18003e750(\"Journal.txt\");\n\
                 \x20 FUN_18003e750(\"Journal.txt\");\n\
                 \x20 FUN_18003e750(DAT_180128cf0);\n\
                 \x20 FUN_18003e750(pcVar2);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "  FUN_18003e750(\"%s: %d hits\");\n  return;\n",
            ),
        );
        program
    }

    #[tokio::test]
    async fn cross_function_flows_append_after_the_per_function_findings_in_listing_order() {
        let program = correlation_program();
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        // The scan order, extended: every per-function finding comes
        // first. Then the cross-function flows, attached to the listing's
        // functions in order — to the earlier end of the pair, whichever
        // way the string flows.
        let order: Vec<(&str, &str)> = result
            .findings
            .iter()
            .map(|finding| (finding.function(), finding.kind()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("FUN_18003ab00", "classified"),
                ("FUN_18003ab00", "classified"),
                ("FUN_18003ab00", "format_string"),
                ("FUN_18003e750", "classified"),
                ("FUN_1800412a0", "classified"),
                ("FUN_18003ab00", "cross_function"),
                ("FUN_18003ab00", "cross_function"),
                ("FUN_18003e750", "cross_function"),
            ]
        );

        // The literal flow: one finding per (passing, receiving, string)
        // triple, no matter how often the call repeats. The first call
        // site's line is the evidence. The string table names no address
        // for this literal, so its address is 0.
        let StringFinding::CrossFunction(flow) = &result.findings[5] else {
            unreachable!("the passing call reads as a cross_function finding");
        };
        assert_eq!(flow.function, "FUN_18003ab00");
        assert_eq!(flow.passing_function, "FUN_18003ab00");
        assert_eq!(flow.receiving_function, "FUN_18003e750");
        assert_eq!(flow.string_value, "Journal.txt");
        assert_eq!(flow.string_address, 0);
        assert_eq!(flow.evidence, "FUN_18003e750(\"Journal.txt\");");
        assert_eq!(flow.confidence, Confidence::new(70));
        assert_eq!(
            result.findings[5].suggestion(),
            "the receiving parameter translates as a string type (`*const i8`/`&str`) and the \
             caller's payload is that string"
        );
        assert_eq!(
            result.findings[5].target(),
            "FUN_18003ab00→FUN_18003e750:Journal.txt"
        );

        // The DAT_ flow resolves against the scan's own string table.
        let StringFinding::CrossFunction(flow) = &result.findings[6] else {
            unreachable!("the DAT_ hand-off reads as a cross_function finding");
        };
        assert_eq!(flow.string_value, "********** Chat logging turned OFF.");
        assert_eq!(flow.string_address, 0x180128cf0);
        assert_eq!(flow.evidence, "FUN_18003e750(DAT_180128cf0);");

        // The later function's string attaches to the earlier end of the
        // pair, naming the later one as the passer.
        let StringFinding::CrossFunction(flow) = &result.findings[7] else {
            unreachable!("the reverse hand-off reads as a cross_function finding");
        };
        assert_eq!(flow.function, "FUN_18003e750");
        assert_eq!(flow.passing_function, "FUN_1800412a0");
        assert_eq!(flow.receiving_function, "FUN_18003e750");
        assert_eq!(flow.string_value, "%s: %d hits");
        assert_eq!(flow.string_address, 0x180129a00);

        // The import call and the variable argument claim no flow: the
        // two ab00 flows are the literal and the DAT_, nothing else. The
        // 412a0 flow attaches to the earlier end of the pair, so 412a0
        // itself carries only its classified string.
        assert_eq!(result.for_function("FUN_18003ab00").count(), 5);
        assert_eq!(result.for_function("FUN_1800412a0").count(), 1);
    }

    #[tokio::test]
    async fn a_function_whose_decompile_failed_contributes_no_body_and_binds_no_edge() {
        // The passing function is missing: its body was never
        // decompiled, so the strings it would have handed over claim
        // nothing.
        let mut program = correlation_program();
        program.fail_decompile = vec!["FUN_18003ab00".to_string()];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        for finding in result
            .findings
            .iter()
            .filter(|f| f.kind() == "cross_function")
        {
            let StringFinding::CrossFunction(flow) = finding else {
                unreachable!("filtered on the kind tag");
            };
            assert_ne!(flow.passing_function, "FUN_18003ab00");
            assert_ne!(flow.receiving_function, "FUN_18003ab00");
        }
        // The e750 ↔ 412a0 flow stands — both bodies were kept.
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|f| f.kind() == "cross_function")
                .count(),
            1
        );

        // The receiving function is missing: a callee whose body was
        // never decompiled is not a kept body, so no edge binds to it
        // either.
        let mut program = correlation_program();
        program.fail_decompile = vec!["FUN_18003e750".to_string()];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "cross_function"),
            "a skipped function fabricates no flow"
        );
    }

    // ============================================================
    // Admitted scan coverage (issue #351)
    // ============================================================

    /// The roster pin's answer, as data. An empty list means the record
    /// names every declared facet exactly once. Each entry is one way
    /// the record drifts from the roster.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    /// The named facet with the given id, for asserting its status and
    /// limitation line.
    fn facet<'a>(coverage: &'a ScanCoverage, id: &str) -> &'a FacetCoverage {
        coverage
            .facets
            .iter()
            .find(|facet| facet.id == id)
            .unwrap_or_else(|| panic!("{id} is named"))
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_coverage_and_a_clean_roster() {
        // The coverage record comes from the scan itself, not from the
        // registry row and not from the CLI. The batch scan phase and the
        // CLI's force-rescan both file the same admission through this
        // one definition. Here every body, every listing string, and
        // every cross-reference was read, so the record is complete and
        // admits nothing.
        let result = StringContextEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh string-context scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Complete);
        assert!(
            roster_faults(&coverage).is_empty(),
            "a fresh document must name every declared facet exactly once"
        );
        for id in DECLARED_FACETS {
            assert_eq!(
                facet(&coverage, id).status,
                CoverageStatus::Complete,
                "{id} read end to end admits nothing"
            );
            assert_eq!(facet(&coverage, id).limitation, None);
        }
    }

    #[tokio::test]
    async fn a_failed_string_listing_makes_that_facet_unavailable_with_its_reason() {
        // A failed listing is not silence; it is an admission. The
        // program's strings were there to read but never arrived, so the
        // facet says so and gives its reason. The body-parsed findings
        // and the rest of the record still stand.
        let mut program = program();
        program.fail_strings = true;
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("the scan survives a failed string listing");
        let coverage = result
            .metadata
            .coverage
            .expect("a degraded scan states its coverage too");
        assert_eq!(
            coverage.status,
            CoverageStatus::Partial,
            "one facet falling short makes the whole picture partial"
        );
        assert!(roster_faults(&coverage).is_empty());
        assert_eq!(
            facet(&coverage, "function-bodies").status,
            CoverageStatus::Complete
        );
        assert_eq!(
            facet(&coverage, "program-strings").status,
            CoverageStatus::Unavailable,
            "the strings were not read, and the record says why"
        );
        assert_eq!(
            facet(&coverage, "program-strings").limitation.as_deref(),
            Some("program string listing unreadable")
        );
        assert_eq!(
            facet(&coverage, "string-xrefs").status,
            CoverageStatus::Complete,
            "with no listing strings there was no cross-reference to ask for"
        );
    }

    #[tokio::test]
    async fn every_failed_cross_reference_lookup_makes_that_facet_unavailable() {
        // The fallback asked and nothing answered, so the xref facet is
        // unavailable with its reason. Each failed address counts once,
        // no matter how many body-empty functions retried it.
        let mut program = program();
        program.fail_xrefs = true;
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let coverage = result
            .metadata
            .coverage
            .expect("the degraded scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert!(roster_faults(&coverage).is_empty());
        assert_eq!(
            facet(&coverage, "function-bodies").status,
            CoverageStatus::Complete
        );
        assert_eq!(
            facet(&coverage, "program-strings").status,
            CoverageStatus::Complete
        );
        assert_eq!(
            facet(&coverage, "string-xrefs").status,
            CoverageStatus::Unavailable
        );
        assert_eq!(
            facet(&coverage, "string-xrefs").limitation.as_deref(),
            Some("no string cross-reference could be read"),
            "the fallback read nothing across every string it asked about"
        );
    }

    #[tokio::test]
    async fn some_unreadable_cross_reference_lookups_leave_the_facet_partial() {
        // One address answered and one never did, so the facet is
        // partial. It counts the lookup that was attempted and never
        // answered.
        let mut program = program();
        program.fail_xref_addrs = vec![0x180129a00];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let coverage = result
            .metadata
            .coverage
            .expect("the partial scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert!(roster_faults(&coverage).is_empty());
        assert_eq!(
            facet(&coverage, "string-xrefs").status,
            CoverageStatus::Partial
        );
        assert_eq!(
            facet(&coverage, "string-xrefs").limitation.as_deref(),
            Some("1 string cross-reference lookup unreadable"),
            "the answered lookups count as read, the failed one as the gap"
        );
    }

    #[tokio::test]
    async fn an_unreached_body_is_admitted_by_name_on_its_own_facet() {
        // A decompile failure is admitted on its own facet only. The
        // other two facets stand complete, so this admission cannot hide
        // behind them or blur into them.
        let mut program = program();
        program.fail_decompile = vec!["FUN_18003e750".into()];
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let coverage = result
            .metadata
            .coverage
            .expect("a partial scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert!(roster_faults(&coverage).is_empty());
        assert_eq!(
            facet(&coverage, "function-bodies").limitation.as_deref(),
            Some("1 function body unreached: FUN_18003e750")
        );
        assert_eq!(
            facet(&coverage, "program-strings").status,
            CoverageStatus::Complete
        );
        assert_eq!(
            facet(&coverage, "string-xrefs").status,
            CoverageStatus::Complete
        );
    }

    #[tokio::test]
    async fn the_bodies_line_is_capped_at_five_names_and_counts_the_nameless() {
        // Short admission, bounded counts: six decompile failures name
        // five of them and fold the sixth into a count. A nameless
        // listing entry counts toward the total but does not take a name
        // slot.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = FakeProgram::default();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(summary(name));
            if index >= 6 {
                program
                    .bodies
                    .insert(name.clone(), function(name, "  return;\n"));
            }
        }
        program.fail_decompile = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = StringContextEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let coverage = result
            .metadata
            .coverage
            .expect("a partial scan states its coverage");
        let bodies = facet(&coverage, "function-bodies");
        assert_eq!(bodies.status, CoverageStatus::Partial);
        assert_eq!(
            bodies.limitation.as_deref(),
            Some(
                "7 function bodies unreached: FUN_body_0000, FUN_body_0001, \
                 FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
            ),
            "six named failures plus one nameless entry: five names, the \
             rest counted, the count covering both"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
        let mut coverage = coverage_stamp(&[], 0, false, 0, 0);
        coverage
            .facets
            .retain(|facet| facet.id != "program-strings");
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `program-strings` is missing from the record"],
            "an engine quietly dropping one of its facets fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_facet_is_doubled() {
        let mut coverage = coverage_stamp(&[], 0, true, 0, 0);
        coverage.facets.push(coverage.facets[1].clone());
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `program-strings` appears 2 times in the record"],
            "a facet crowded into two entries fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
        let mut coverage = coverage_stamp(&[], 0, false, 0, 0);
        coverage.facets.push(FacetCoverage {
            id: "format-strings".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `format-strings`, a facet the engine never declared"],
            "an entry outside the declared roster fails loudly — format \
             strings are read off the bodies, not from a region of their own"
        );
    }
}
