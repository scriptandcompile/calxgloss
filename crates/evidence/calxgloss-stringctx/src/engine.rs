//! String-context scan orchestration.
//!
//! [`StringContextEngine`] runs the string classifier, the hybrid
//! string-to-function mapper, and the format-string engine over one open
//! Ghidra program and assembles their findings into a single
//! [`StringContextResult`] with its scan provenance.
//!
//! The scan is one sequential pass over the function listing: one
//! `strings()` call up front, one decompile per function, and xref
//! lookups only where a function's body parse found nothing — the hybrid
//! rule that keeps a scan cheap. Classification runs once per program
//! string and is reused across every function that uses it, and xref
//! responses are cached per string address so the fallback never asks
//! the same question twice.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient, StringLiteral, Xref};
use tracing::{info, warn};

use crate::classify::StringClassifyEngine;
use crate::error::Result;
use crate::format_str::FormatStringEngine;
use crate::hybrid_mapper::{BODY_CONFIDENCE, HybridXrefMapper, XREF_CONFIDENCE};
use crate::types::{
    ClassifiedString, Confidence, FormatStringUse, ScanMetadata, StringClassification,
    StringContextResult, StringFinding, StringSource,
};

/// The program a string-context scan reads.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned listings, bodies, strings, and xrefs so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven from
/// an orchestrating task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;

    /// Every string literal in the program, in listing order.
    fn strings(&self) -> impl std::future::Future<Output = Result<Vec<StringLiteral>>> + Send;

    /// The references pointing at `address`, as the client parsed them.
    fn xrefs_to(&self, address: u64)
    -> impl std::future::Future<Output = Result<Vec<Xref>>> + Send;
}

impl ScanSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(self.list_strings(None).await?)
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        Ok(self.xrefs_to(address, None).await?)
    }
}

/// Orchestrates the classifier, hybrid mapper, and format-string engine
/// into one [`StringContextResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned program data; [`new`](Self::new)
/// builds one over a live [`GhidraClient`]. Each sub-engine carries no
/// per-scan state — [`with_classifier`](Self::with_classifier),
/// [`with_mapper`](Self::with_mapper), and
/// [`with_format_engine`](Self::with_format_engine) swap one whole — so
/// one of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct StringContextEngine<S = GhidraClient> {
    source: S,
    classifier: StringClassifyEngine,
    mapper: HybridXrefMapper,
    format_engine: FormatStringEngine,
}

impl StringContextEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the
    /// classifier's standard pattern sets.
    pub fn new(client: &GhidraClient) -> StringContextEngine<GhidraClient> {
        StringContextEngine {
            source: client.clone(),
            classifier: StringClassifyEngine::with_default_patterns(),
            mapper: HybridXrefMapper::new(),
            format_engine: FormatStringEngine::new(),
        }
    }
}

impl<S> StringContextEngine<S> {
    /// An engine whose program data comes from `source`, scanning with
    /// the classifier's standard pattern sets.
    pub fn with_source(source: S) -> Self {
        StringContextEngine {
            source,
            classifier: StringClassifyEngine::with_default_patterns(),
            mapper: HybridXrefMapper::new(),
            format_engine: FormatStringEngine::new(),
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

    /// Map the program's strings to its functions across `binary`,
    /// decompiling each function exactly once and consulting xrefs only
    /// where a body parse came up empty.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The findings
    /// follow the function listing — function by function, and within
    /// one function the classified strings, then the format-string
    /// calls — so two scans of the same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning, as is a nameless listing entry;
    /// a failed xref lookup costs only that string's fallback coverage.
    /// Only a failure of the listings themselves — the function listing
    /// or the string listing, the server being down — aborts the run,
    /// since then nothing can be scanned.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<StringContextResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        let program_strings = self.source.strings().await?;
        let string_table: HashMap<u64, String> = program_strings
            .iter()
            .map(|string| (string.address, string.value.clone()))
            .collect();

        // Classification is a property of the string, not of the
        // function using it: one pass over the program's strings, and
        // every function that touches one reads the same answer.
        let mut classifications: HashMap<String, (StringClassification, &'static str)> =
            HashMap::new();
        // The fallback asks each string address at most once per scan.
        let mut xref_cache: HashMap<u64, Vec<Xref>> = HashMap::new();

        let mut findings = Vec::new();
        let mut skipped = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing
                // can be said about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
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

            // The hybrid rule: a function whose body parse found strings
            // gets no xref lookups; only a function the body came up
            // empty on is covered through the xref fallback.
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
                fallback
            } else {
                body_usages
            };

            // A string read as a format string is recorded through its
            // call, not as a plain classified string too.
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
        }

        let mut metadata = ScanMetadata::new(binary);
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
    use calxgloss_ghidra::{FunctionSummary, GhidraError, StringLiteral};
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

    /// A canned program implementing [`ScanSource`], with fetch counters
    /// and failure switches so the orchestration can be watched and
    /// broken without a server.
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
        decompile_fetches: Arc<AtomicUsize>,
        xref_fetches: Arc<AtomicUsize>,
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.decompile_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_decompile.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into());
            }
            self.bodies.get(name).cloned().ok_or_else(|| {
                GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into()
            })
        }

        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            if self.fail_strings {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.literals.clone())
        }

        async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
            self.xref_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_xrefs {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
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

        // FUN_18003ab00: the literal and the DAT_ reference classify,
        // the sprintf call reads as a format_string finding — and the
        // format string is not also recorded as a classified string.
        let ab00: Vec<&StringFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(ab00.len(), 3);
        assert_eq!(ab00[0].kind(), "classified");
        assert_eq!(ab00[0].target(), "Journal.txt");
        assert_eq!(ab00[1].kind(), "classified");
        assert_eq!(ab00[1].target(), "********** Chat logging turned OFF.");
        assert_eq!(ab00[2].kind(), "format_string");
        assert_eq!(ab00[2].target(), "%s: %d hits");

        // FUN_18003e750 has no strings in its body but is xref'd by the
        // chat-logging string — the fallback covers it.
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
    async fn a_failed_string_listing_aborts_the_scan() {
        let mut program = program();
        program.fail_strings = true;
        assert!(
            StringContextEngine::with_source(program)
                .scan("eqmain.dll")
                .await
                .is_err()
        );
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
}
