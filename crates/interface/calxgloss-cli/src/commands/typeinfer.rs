//! The `typeinfer` command's CLI contribution — infer parameter types
//! for a binary (issue #341, spec #337).
//!
//! The scan shape — building the scan's evidence engine, the scan,
//! persisting, honest degradation — lives in the pipeline's
//! `type-inference` registry row. This module contributes only what
//! belongs to this evidence engine: the cached-document loader, the
//! report printer, and the post-scan step applying `--write-back`
//! through the typeinfer crate's own write-back API, narrowed by the
//! `--confidence-floor`. The generic handler
//! ([`scan_command`](crate::commands::scan_command)) routes the command
//! end to end. A scan run always rebuilds the result — the CLI's
//! refresh-cache contract — and `--show` prints what a cached document
//! holds. The result is filed where the row files it —
//! `re/analysis/typeinfer/{binary}.json` — the same file batch
//! translation reads as prompt context. The run's report and a later
//! `--show` report are the same read of the same document.
//!
//! The write-back step runs on the scan path and on `--show
//! --write-back`. The follow-on report it produces is stored inside the
//! loaded document, so both paths print the main report first and the
//! write-back section second, byte-identically. `--show` alone never
//! loads the Kuna engine.

use std::path::Path;

use anyhow::{Context, Result, bail};
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::ScanRunOptions;
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_typeinfer::types::{Confidence, InferenceMethod, InferredType, TypeInferenceResult};
use calxgloss_typeinfer::write_back::{WriteBack, WriteBackReport};
use chrono::DateTime;

use crate::commands::scan_command::{
    PostScanFuture, ScanContribution, ScanContributionSteps, ScanFlags,
};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The document this entry loads and prints: the filed inference result
/// plus, when a `--write-back` pass ran, the report it produced and the
/// floor it ran at. The follow-on report is stored inside this document,
/// so the printer — the same printer on the scan path and on `--show` —
/// renders both sections in one order, and the handler never has to
/// sequence them itself.
struct FiledInference {
    /// The filed inference result, exactly as the persistor reads it.
    result: TypeInferenceResult,
    /// The write-back report and the floor it was produced at, when a
    /// `--write-back` pass ran over this document.
    write_back: Option<(u8, WriteBackReport)>,
}

/// The `typeinfer` entry in the CLI-side contribution table: it serves
/// the registry's `type-inference` row and supplies this command's
/// loader, printer, and write-back post-scan step. The command's flags
/// never change the row's options — the entry hands it plain defaults.
/// The write-back is the entry's own step, and it interprets the flags
/// itself.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "type-inference",
        load: load_filed_inference,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: Some(write_back_surviving_inferences),
        show_loads_program: |flags| flags.write_back,
    })
}

/// Read the filed result through the evidence engine's own persistor,
/// wrapped in the entry's document. A missing result arrives with the
/// remediation wording that names the exact command to produce it.
fn load_filed_inference(workspace: &Path, binary: &str) -> Result<FiledInference> {
    let result = TypeInferPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached type inference result for {binary}; \
                 run `calxgloss typeinfer --binary {binary}` to produce one"
            )
        })?;
    Ok(FiledInference {
        result,
        write_back: None,
    })
}

/// Print the report from the loaded document: the inference summary
/// first, then the write-back section — and only when this very command
/// line ran a write-back pass. This is the order the old dedicated
/// handler printed in; it now lives in the document itself, so both
/// paths print the same bytes.
fn print_report(filed: &FiledInference, workspace: &Path, binary: &str) -> Result<()> {
    print_type_inference_report(
        &filed.result,
        &TypeInferPersistor::new(workspace).path_for(binary),
    );
    if let Some((floor, report)) = &filed.write_back {
        print_write_back_report(report, *floor);
    }
    Ok(())
}

/// The post-scan step: with `--write-back`, apply the surviving
/// inferences into the open program through the typeinfer crate's own
/// write-back seam — the Kuna engine's type-write API, not a
/// re-implementation — keeping only records at the confidence floor or
/// above, and leave the produced report in the document for the printer.
/// Without the flag the step does nothing; the document is read-only in
/// that run. The Kuna source answers both seams — the read cache never
/// implements the write trait (ADR-0020), and the generic handler hands
/// this entry the same settings-aware Kuna load the dedicated handler
/// used.
fn write_back_surviving_inferences<'a>(
    source: &'a PipelineSource,
    _workspace: &'a Path,
    binary: &'a str,
    flags: &'a ScanFlags,
    filed: &'a mut FiledInference,
) -> PostScanFuture<'a> {
    Box::pin(async move {
        if !flags.write_back {
            return Ok(());
        }
        let PipelineSource::Kuna(kuna) = source else {
            bail!(
                "the type-inference write-back needs the in-process Kuna source, \
                 and the scan handed a cached read source"
            );
        };
        let report = WriteBack::new(kuna, kuna, Confidence::new(flags.confidence_floor))
            .apply(&filed.result)
            .await
            .with_context(|| format!("Type write-back failed for {binary}"))?;
        filed.write_back = Some((flags.confidence_floor, report));
        Ok(())
    })
}

/// Print a summary of an inference result: where it is filed, when it was
/// built, and what the surviving inferences say.
fn print_type_inference_report(result: &TypeInferenceResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Type Inference — {}", result.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    let scanned = DateTime::from_timestamp(result.metadata.scanned_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("unix {}", result.metadata.scanned_at));
    println_content(format!(
        "  {}{} {}",
        white_bold("Scanned:   "),
        scanned,
        dim(&format!("({}s)", result.metadata.duration_secs))
    ));
    println!();

    // Inferences, broken down by the record kind the union carries.
    let kind_breakdown: Vec<String> = kind_breakdown(result);
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Inferences:"),
        result.inferences.len(),
        dim(&kind_breakdown.join(", "))
    ));

    // And by the detector method that produced each one.
    let method_breakdown: Vec<String> = method_breakdown(result);
    print_method_breakdown(&method_breakdown);

    let top_confidence = result.inferences.iter().map(|i| i.confidence()).max();
    println_content(format!(
        "  {}{}",
        white_bold("Top conf:  "),
        match top_confidence {
            Some(confidence) => confidence_color(confidence.value())(&confidence.to_string()),
            None => dim("(none)"),
        }
    ));

    // The scan's own admission, printed beside the counts it qualifies
    // (issue #351): the shared type's bounded line, shown under
    // `Coverage:` and only when there is something to admit. The line
    // names only listings that never arrived and edges that refused — a
    // function with no inferences under a complete record was examined
    // and is clean.
    print_coverage(result.metadata.coverage.as_ref());
    println!();

    if !result.inferences.is_empty() {
        hsep();
        println_content("  Inferences:");
        hsep();
        for inference in result.inferences.iter().take(DETAIL_LIMIT) {
            let confidence = inference.confidence();
            println_content(format!(
                "  ●  {:<13} {:<12} {:<8} {}",
                inference.function(),
                inference_target(inference),
                inference.inferred_type(),
                confidence_color(confidence.value())(&format!(
                    "{confidence} {}",
                    inference_method(inference)
                ))
            ));
        }
        print_hidden_count("inference", result.inferences.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan inferred nothing — no this-pointer, size, or known-signature readings were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Type inference ready — batch translation reads it as prompt context.",
            green_bold("✓")
        );
    }
    println!();
}

/// Print the outcome of a `--write-back` pass: what landed in the
/// program, what was skipped and why, and what the program refused.
fn print_write_back_report(report: &WriteBackReport, floor: u8) {
    println!();
    hsep_bold();
    println_content(format!("  Type Write-Back — floor {floor}"));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("Applied:   "),
        green_bold(&report.applied.to_string())
    ));
    println_content(format!(
        "  {}{}{}",
        white_bold("Types:     "),
        report.types_created,
        dim(" (named types created)")
    ));
    println_content(format!(
        "  {}{}{}",
        white_bold("Skipped:   "),
        report.skipped.len(),
        dim(" (below floor, concrete slot, not found)")
    ));
    println_content(format!(
        "  {}{}",
        white_bold("Failed:    "),
        if report.failed.is_empty() {
            report.failed.len().to_string()
        } else {
            red_bold(&report.failed.len().to_string())
        }
    ));
    println!();

    if !report.skipped.is_empty() {
        hsep();
        println_content("  Skipped:");
        hsep();
        for skipped in report.skipped.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<28} {}",
                skipped.target,
                dim(&skipped.reason.to_string())
            ));
        }
        print_hidden_count("skipped record", report.skipped.len());
        println!();
    }

    if !report.failed.is_empty() {
        hsep();
        println_content("  Failed:");
        hsep();
        for failed in report.failed.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<28} {}",
                failed.target,
                red_bold(&failed.error)
            ));
        }
        print_hidden_count("failed write", report.failed.len());
        println!();
    }

    hsep_bold();
    if report.applied == 0 && report.types_created == 0 {
        println!(
            "  {} Nothing was written back — every record was skipped or refused.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} {} records written back into the program.",
            green_bold("✓"),
            report.applied
        );
    }
    println!();
}

/// Print the detector-method breakdown, wrapping onto indented
/// continuation lines when the list outgrows one report line.
fn print_method_breakdown(items: &[String]) {
    const LINE_WIDTH: usize = 78;
    if items.is_empty() {
        println_content("  Methods:   (none)");
        return;
    }
    let mut line = String::from("  Methods:   ");
    for (index, item) in items.iter().enumerate() {
        let separator = if index == 0 { "" } else { ", " };
        if line.len() + separator.len() + item.len() > LINE_WIDTH {
            println_content(&line);
            line = format!("  {:<11}", "");
            line.push_str(item);
        } else {
            line.push_str(separator);
            line.push_str(item);
        }
    }
    println_content(&line);
}

/// Which record kind an inference is — the union's six variants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InferenceKind {
    Param,
    Local,
    CallSite,
    Return,
    Convention,
    Direction,
}

/// How many inferences of one record kind the result carries.
fn count_kind(result: &TypeInferenceResult, kind: InferenceKind) -> usize {
    result
        .inferences
        .iter()
        .filter(|inference| {
            matches!(
                (kind, inference),
                (InferenceKind::Param, InferredType::Param(_))
                    | (InferenceKind::Local, InferredType::Local(_))
                    | (InferenceKind::CallSite, InferredType::CallSite(_))
                    | (InferenceKind::Return, InferredType::Return(_))
                    | (InferenceKind::Convention, InferredType::Convention(_))
                    | (InferenceKind::Direction, InferredType::Direction(_))
            )
        })
        .count()
}

/// The kind breakdown the report prints: every record kind carrying at
/// least one inference, with its count, in report order.
fn kind_breakdown(result: &TypeInferenceResult) -> Vec<String> {
    [
        ("param", count_kind(result, InferenceKind::Param)),
        ("local", count_kind(result, InferenceKind::Local)),
        ("call_site", count_kind(result, InferenceKind::CallSite)),
        ("return", count_kind(result, InferenceKind::Return)),
        ("convention", count_kind(result, InferenceKind::Convention)),
        ("direction", count_kind(result, InferenceKind::Direction)),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect()
}

/// The method breakdown the report prints: every detector method that
/// produced at least one inference, with its count. The list names
/// every variant of the closed method set — a new detector whose method
/// is missing here is what the completeness test catches.
fn method_breakdown(result: &TypeInferenceResult) -> Vec<String> {
    [
        InferenceMethod::VtableCall,
        InferenceMethod::FirstParamUsage,
        InferenceMethod::ComInterface,
        InferenceMethod::StringFunction,
        InferenceMethod::IntegerBitPattern,
        InferenceMethod::PointerArithmetic,
        InferenceMethod::KnownSignature,
        InferenceMethod::CrossFunction,
        InferenceMethod::AssignmentChain,
        InferenceMethod::ReturnUsage,
        InferenceMethod::ParamDirection,
        InferenceMethod::Mangling,
        InferenceMethod::MangledConvention,
        InferenceMethod::ImportDecoration,
        InferenceMethod::CalleeEpilogue,
        InferenceMethod::CallerCleanup,
        InferenceMethod::X64Shape,
        InferenceMethod::CorroboratedConvention,
        InferenceMethod::CallSiteConvention,
    ]
    .into_iter()
    .map(|method| {
        (
            method,
            result
                .inferences
                .iter()
                .filter(|inference| inference_method(inference) == method)
                .count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(method, count)| format!("{method} {count}"))
    .collect()
}

/// The detector method behind an inference — the union carries the
/// payload per variant.
fn inference_method(inference: &InferredType) -> InferenceMethod {
    match inference {
        InferredType::Param(record) => record.method,
        InferredType::Local(record) => record.method,
        InferredType::CallSite(record) => record.method,
        InferredType::Return(record) => record.method,
        InferredType::Convention(record) => record.method,
        InferredType::Direction(record) => record.method,
    }
}

/// The name of what an inference types: a parameter (its decompiled
/// name, falling back to its position), a local variable, a call-site
/// argument written as the call site that produced it, a function's
/// return, a function's calling convention, or a parameter's direction —
/// written with the parameter's name, so a direction reading prints
/// beside the type reading for the same parameter.
fn inference_target(inference: &InferredType) -> String {
    match inference {
        InferredType::Param(record) => record
            .param_name
            .clone()
            .unwrap_or_else(|| format!("param_{}", record.param_index + 1)),
        InferredType::Local(record) => record.variable_name.clone(),
        InferredType::CallSite(record) => match record.arg_name.as_deref() {
            Some(arg) => format!("{}({arg})", record.callee),
            None => format!("{} arg {}", record.callee, record.arg_index + 1),
        },
        InferredType::Return(_) => "return".to_string(),
        // A call-site reading names its callee in the label, so it
        // prints beside the caller's own convention instead of under the
        // same label.
        InferredType::Convention(record) => match record.callee.as_deref() {
            Some(callee) => format!("{callee} convention"),
            None => "convention".to_string(),
        },
        InferredType::Direction(record) => {
            let param = record
                .param_name
                .clone()
                .unwrap_or_else(|| format!("param_{}", record.param_index + 1));
            format!("{param} direction")
        }
    }
}

/// Color a 0–100 confidence score the way the other reports color pass rates.
fn confidence_color(confidence: u8) -> fn(&str) -> String {
    if confidence >= 70 {
        green_bold
    } else if confidence >= 50 {
        yellow_bold
    } else {
        red_bold
    }
}

/// The "…and N more" line a detail section ends with when it collapsed.
fn print_hidden_count(noun: &str, total: usize) {
    if total > DETAIL_LIMIT {
        println_content(format!(
            "  {} …and {} more {noun}",
            dim("●"),
            total - DETAIL_LIMIT
        ));
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_typeinfer::types::{
        CallingConvention, Direction, InferenceScope, InferredCallType, InferredConvention,
        InferredLocalType, InferredParamDirection, InferredParamType, InferredReturnType,
    };

    fn param(function: &str, method: InferenceMethod) -> InferredType {
        InferredType::Param(InferredParamType {
            function: function.into(),
            param_index: 0,
            param_name: Some("param_1".into()),
            inferred_type: "Widget *".into(),
            method,
            scope: InferenceScope::Function,
            confidence: Confidence::new(80),
            evidence: "evidence".into(),
        })
    }

    fn result_with(inferences: Vec<InferredType>) -> TypeInferenceResult {
        TypeInferenceResult {
            metadata: calxgloss_typeinfer::types::ScanMetadata::new("eqmain.dll"),
            inferences,
        }
    }

    #[test]
    fn the_kind_breakdown_names_every_record_kind_the_union_carries() {
        let result = result_with(vec![
            param("FUN_18003ab00", InferenceMethod::VtableCall),
            InferredType::Local(InferredLocalType {
                function: "FUN_18003ab00".into(),
                variable_name: "local_8".into(),
                inferred_type: "char *".into(),
                method: InferenceMethod::AssignmentChain,
                scope: InferenceScope::Function,
                confidence: Confidence::new(60),
                evidence: "local_8 = param_1;".into(),
            }),
            InferredType::CallSite(InferredCallType {
                function: "FUN_1800412a0".into(),
                callee: "CloseHandle".into(),
                arg_index: 0,
                arg_name: Some("param_2".into()),
                inferred_type: "void *".into(),
                method: InferenceMethod::KnownSignature,
                scope: InferenceScope::Program,
                confidence: Confidence::new(75),
                evidence: "CloseHandle(param_2);".into(),
            }),
            InferredType::Return(InferredReturnType {
                function: "FUN_180051c00".into(),
                inferred_type: "char *".into(),
                method: InferenceMethod::ReturnUsage,
                scope: InferenceScope::Function,
                confidence: Confidence::new(60),
                evidence: "local_8 = FUN_180051c00();".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "?paint@Widget@@QAEXXZ".into(),
                callee: None,
                convention: CallingConvention::Thiscall,
                method: InferenceMethod::MangledConvention,
                confidence: Confidence::new(90),
                evidence: "?paint@Widget@@QAEXXZ".into(),
            }),
            InferredType::Direction(InferredParamDirection {
                function: "FUN_18003ab00".into(),
                param_index: 0,
                param_name: Some("param_1".into()),
                direction: Direction::Out,
                method: InferenceMethod::ParamDirection,
                scope: InferenceScope::Function,
                confidence: Confidence::new(75),
                evidence: "*param_1 = 0;".into(),
            }),
        ]);
        assert_eq!(
            kind_breakdown(&result),
            [
                "param 1",
                "local 1",
                "call_site 1",
                "return 1",
                "convention 1",
                "direction 1",
            ]
        );
    }

    #[test]
    fn the_method_breakdown_names_every_detector_method_in_the_closed_set() {
        // One record per method of the closed set: the breakdown must
        // account for every channel, so a new method missing from the
        // report list fails here rather than going unreported.
        let result = result_with(vec![
            param("FUN_1", InferenceMethod::VtableCall),
            param("FUN_2", InferenceMethod::FirstParamUsage),
            param("FUN_3", InferenceMethod::ComInterface),
            param("FUN_4", InferenceMethod::StringFunction),
            param("FUN_5", InferenceMethod::IntegerBitPattern),
            param("FUN_6", InferenceMethod::PointerArithmetic),
            param("FUN_7", InferenceMethod::KnownSignature),
            param("FUN_8", InferenceMethod::CrossFunction),
            InferredType::Local(InferredLocalType {
                function: "FUN_9".into(),
                variable_name: "local_8".into(),
                inferred_type: "char *".into(),
                method: InferenceMethod::AssignmentChain,
                scope: InferenceScope::Function,
                confidence: Confidence::new(60),
                evidence: "local_8 = param_1;".into(),
            }),
            InferredType::Return(InferredReturnType {
                function: "FUN_10".into(),
                inferred_type: "char *".into(),
                method: InferenceMethod::ReturnUsage,
                scope: InferenceScope::Function,
                confidence: Confidence::new(60),
                evidence: "local_8 = FUN_10();".into(),
            }),
            param("FUN_11", InferenceMethod::Mangling),
            InferredType::Convention(InferredConvention {
                function: "?paint@Widget@@QAEXXZ".into(),
                callee: None,
                convention: CallingConvention::Thiscall,
                method: InferenceMethod::MangledConvention,
                confidence: Confidence::new(90),
                evidence: "?paint@Widget@@QAEXXZ".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "CreateFileA@28".into(),
                callee: None,
                convention: CallingConvention::Stdcall,
                method: InferenceMethod::ImportDecoration,
                confidence: Confidence::new(85),
                evidence: "CreateFileA@28".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "FUN_18003e750".into(),
                callee: None,
                convention: CallingConvention::Stdcall,
                method: InferenceMethod::CalleeEpilogue,
                confidence: Confidence::new(80),
                evidence: "00401004  RET 0xC".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "FUN_1800412a0".into(),
                callee: None,
                convention: CallingConvention::Cdecl,
                method: InferenceMethod::CallerCleanup,
                confidence: Confidence::new(70),
                evidence: "00401108  ADD ESP, 0x8".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "FUN_18003e750".into(),
                callee: None,
                convention: CallingConvention::MicrosoftX64,
                method: InferenceMethod::X64Shape,
                confidence: Confidence::new(65),
                evidence: "140001000  SUB RSP, 0x28".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "paint@12".into(),
                callee: None,
                convention: CallingConvention::Stdcall,
                method: InferenceMethod::CorroboratedConvention,
                confidence: Confidence::new(92),
                evidence: "00401008  RET 0xC; no caller cleanup at FUN_caller".into(),
            }),
            InferredType::Convention(InferredConvention {
                function: "FUN_caller".into(),
                callee: Some("paint@12".into()),
                convention: CallingConvention::Stdcall,
                method: InferenceMethod::CallSiteConvention,
                confidence: Confidence::new(92),
                evidence: "00401103  CALL paint@12".into(),
            }),
            InferredType::Direction(InferredParamDirection {
                function: "FUN_19".into(),
                param_index: 0,
                param_name: Some("param_1".into()),
                direction: Direction::Out,
                method: InferenceMethod::ParamDirection,
                scope: InferenceScope::Function,
                confidence: Confidence::new(75),
                evidence: "*param_1 = 0;".into(),
            }),
        ]);
        let breakdown = method_breakdown(&result);
        for method in [
            InferenceMethod::VtableCall,
            InferenceMethod::FirstParamUsage,
            InferenceMethod::ComInterface,
            InferenceMethod::StringFunction,
            InferenceMethod::IntegerBitPattern,
            InferenceMethod::PointerArithmetic,
            InferenceMethod::KnownSignature,
            InferenceMethod::CrossFunction,
            InferenceMethod::AssignmentChain,
            InferenceMethod::ReturnUsage,
            InferenceMethod::ParamDirection,
            InferenceMethod::Mangling,
            InferenceMethod::MangledConvention,
            InferenceMethod::ImportDecoration,
            InferenceMethod::CalleeEpilogue,
            InferenceMethod::CallerCleanup,
            InferenceMethod::X64Shape,
            InferenceMethod::CorroboratedConvention,
            InferenceMethod::CallSiteConvention,
        ] {
            assert!(
                breakdown.contains(&format!("{method} 1")),
                "{method} missing from {breakdown:?}"
            );
        }
    }

    #[test]
    fn a_convention_record_reports_as_convention() {
        let record = InferredType::Convention(InferredConvention {
            function: "CreateFileA@28".into(),
            callee: None,
            convention: CallingConvention::Stdcall,
            method: InferenceMethod::ImportDecoration,
            confidence: Confidence::new(85),
            evidence: "CreateFileA@28".into(),
        });
        assert_eq!(inference_target(&record), "convention");
        assert_eq!(inference_method(&record), InferenceMethod::ImportDecoration);
        assert_eq!(record.inferred_type(), "stdcall");
    }

    #[test]
    fn a_direction_record_reports_beside_its_parameter() {
        // The target line names the parameter's direction so the reading
        // stands beside the parameter's type reading in the list, and
        // the value column carries the direction word.
        let record = InferredType::Direction(InferredParamDirection {
            function: "FUN_18003ab00".into(),
            param_index: 1,
            param_name: Some("param_2".into()),
            direction: Direction::InOut,
            method: InferenceMethod::ParamDirection,
            scope: InferenceScope::Function,
            confidence: Confidence::new(75),
            evidence: "*param_2 = &local_8;".into(),
        });
        assert_eq!(inference_target(&record), "param_2 direction");
        assert_eq!(inference_method(&record), InferenceMethod::ParamDirection);
        assert_eq!(record.inferred_type(), "inout");
    }
}
