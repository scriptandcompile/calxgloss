//! The `classify` command — analyze DLLs and assign categories.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss::ProgressEvent;
use calxgloss::TranslationEvents;
use calxgloss_analysis::Analyzer;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::GitManager;
use calxgloss_pal::ApiMappings;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// Handle the `classify` subcommand: analyzes DLLs and writes classification records.
pub async fn handle_classify(
    dlls: &[String],
    target_dir: &Path,
    workspace: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
) -> Result<()> {
    info!(count = dlls.len(), "Classifying DLLs");

    // Initialize Ghidra client (needed only for fallback when PE parse fails)
    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;

    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }

    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize analyzer
    let api_mappings = ApiMappings::default();
    let analyzer = Analyzer::new(ghidra, api_mappings);

    // Symbol counts come from PE headers on disk — accurate per-DLL.
    let classifications = analyzer.classify_dlls(dlls, target_dir).await?;

    // Write classification records to disk and commit.
    let classify_dir = workspace.join("re").join("classify");
    std::fs::create_dir_all(&classify_dir).with_context(|| {
        format!(
            "Failed to create classification directory: {}",
            classify_dir.display()
        )
    })?;

    let mut written = Vec::new();
    for c in &classifications {
        let sanitized: String = c
            .binary
            .chars()
            .map(|ch| match ch {
                '/' | '\\' => '_',
                other => other,
            })
            .collect();
        let record_path = classify_dir.join(format!("{sanitized}.json"));
        let json = serde_json::to_string_pretty(&c)
            .with_context(|| format!("Failed to serialize classification for {}", c.binary))?;
        std::fs::write(&record_path, &json)
            .with_context(|| format!("Failed to write classification record for {}", c.binary))?;
        let record_path_str = record_path.to_string_lossy().to_string();
        written.push(record_path_str.clone());
        info!(binary = %c.binary, record = %record_path_str, "Wrote classification record");

        // Emit classification complete event for live mode
        if let Some(events) = events {
            events.emit(ProgressEvent::ClassificationComplete {
                binary: c.binary.clone().into(),
                category: format!("{:?}", c.category),
                strategy: format!("{:?}", c.strategy),
                crate_replacement: c.crate_replacement.clone(),
                exported_symbols: c.exports_count,
                imported_symbols: c.imports_count,
            });
        }
    }

    // Commit classification records to git (unless skip_git).
    if !skip_git
        && !written.is_empty()
        && let Ok(git) = GitManager::open(workspace)
    {
        let _commit = git
            .commit_to_main(
                &format!(
                    "classify: record classification for {} DLL(s)",
                    written.len()
                ),
                &written,
            )
            .context("Failed to commit classification records");
    }

    // Generate shim layer suggestions for CrateReplacement DLLs.
    let report = analyzer.suggest_shim_layers(&classifications);
    if !report.is_empty() {
        let shim_dir = workspace.join("re").join("shims");
        std::fs::create_dir_all(&shim_dir).with_context(|| {
            format!(
                "Failed to create shim suggestions directory: {}",
                shim_dir.display()
            )
        })?;

        let suggestion_path = shim_dir.join("suggestions.json");
        let json = serde_json::to_string_pretty(&report)
            .with_context(|| "Failed to serialize shim suggestions report")?;
        std::fs::write(&suggestion_path, &json).with_context(|| {
            format!(
                "Failed to write shim suggestions to {}",
                suggestion_path.display()
            )
        })?;
        info!(
            count = report.total_dlls(),
            suggestion_path = %suggestion_path.display(),
            "Wrote shim layer suggestions"
        );

        // Commit shim suggestions to git (unless skip_git).
        if !skip_git && let Ok(git) = GitManager::open(workspace) {
            let _commit = git
                .commit_to_main(
                    &format!(
                        "shim: generate suggestions for {} crate-replacement DLL(s)",
                        report.total_dlls()
                    ),
                    &[suggestion_path.to_string_lossy().to_string()],
                )
                .context("Failed to commit shim suggestions");
        }
    }

    // Print report
    print_classification_report(&classifications, &report);

    info!(count = classifications.len(), "Classification complete");
    Ok(())
}
