// Tests for the module above, split out of the file they test.
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
    let StringFinding::Classified(record) = result.for_function("FUN_18003ab00").next().unwrap()
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
