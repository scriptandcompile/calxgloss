//! The `typeinfer` command — infer parameter types for the open binary.
//!
//! Runs the three inference detectors — C++ this-pointer detection,
//! parameter-size detection, and known-type propagation — against the
//! program currently open in Ghidra and saves the result to
//! `re/analysis/typeinfer/{dll}.json` in the workspace. Batch translation
//! runs the same scan before its first batch when no result is cached;
//! this command is the manual entry point: it rebuilds the result on
//! demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_typeinfer::engine::TypeInferEngine;
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_typeinfer::types::{InferenceMethod, InferredType, TypeInferenceResult};
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `typeinfer` subcommand: infer parameter types for `dll`,
/// or print the cached result when `show` is set.
pub async fn handle_typeinfer(
    dll: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = TypeInferPersistor::new(workspace);

    if show {
        let result = persistor.load(dll).with_context(|| {
            format!(
                "No cached type inference result for {dll}; \
                 run `calxgloss typeinfer --dll {dll}` to produce one"
            )
        })?;
        print_type_inference_report(&result, &persistor.path_for(dll));
        return Ok(());
    }

    info!(dll, workspace = %workspace.display(), "Inferring parameter types");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let engine = TypeInferEngine::new(&ghidra);
    let result = engine
        .scan(dll)
        .await
        .with_context(|| format!("Type inference failed for {dll}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the type inference result for {dll}"))?;

    print_type_inference_report(&result, &persistor.path_for(dll));
    Ok(())
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
    let kind_breakdown: Vec<String> = [
        ("param", count_kind(result, InferenceKind::Param)),
        ("local", count_kind(result, InferenceKind::Local)),
        ("call_site", count_kind(result, InferenceKind::CallSite)),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Inferences:"),
        result.inferences.len(),
        dim(&kind_breakdown.join(", "))
    ));

    // And by the detector method that produced each one.
    let method_breakdown: Vec<String> = [
        InferenceMethod::VtableCall,
        InferenceMethod::FirstParamUsage,
        InferenceMethod::ComInterface,
        InferenceMethod::StringFunction,
        InferenceMethod::IntegerBitPattern,
        InferenceMethod::PointerArithmetic,
        InferenceMethod::KnownSignature,
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
    .collect();
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

/// Which record kind an inference is — the union's three variants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InferenceKind {
    Param,
    Local,
    CallSite,
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
            )
        })
        .count()
}

/// The detector method behind an inference — the union carries the
/// payload per variant.
fn inference_method(inference: &InferredType) -> InferenceMethod {
    match inference {
        InferredType::Param(record) => record.method,
        InferredType::Local(record) => record.method,
        InferredType::CallSite(record) => record.method,
    }
}

/// The name of what an inference types: a parameter (its decompiled name,
/// falling back to its position), a local variable, or a call-site
/// argument spelled as the site that produced it.
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
