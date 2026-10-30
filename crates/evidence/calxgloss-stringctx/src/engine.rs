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
mod tests;
