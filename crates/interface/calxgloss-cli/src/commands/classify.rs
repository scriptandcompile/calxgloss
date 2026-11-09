//! The `classify` command — analyze DLLs and assign categories.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_analysis::Analyzer;
use calxgloss_git::GitManager;
use calxgloss_pal::ApiMappings;
use calxgloss_types::ClassificationOverrideControl;
use calxgloss_types::ProgressEvent;
use calxgloss_types::TranslationEvents;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// The override handle the classify path consults: the live run's
/// shared handle where one was passed, otherwise one opened over the
/// workspace through the shared module's fallible open (issue #459). A
/// never-filed document is the clean un-overridden state, while corrupt
/// bytes stop the command naming their fault — the classification never
/// runs as if no override had ever stood.
fn override_handle_or_open(
    passed: Option<&ClassificationOverrideControl>,
    workspace: &Path,
) -> Result<ClassificationOverrideControl> {
    match passed {
        Some(control) => Ok(control.clone()),
        None => ClassificationOverrideControl::try_open(workspace)
            .with_context(|| "cannot read the classification override records"),
    }
}

/// Handle the `classify` subcommand: analyzes DLLs and writes classification records.
///
/// The classification-override handle (issue #97, W2.8) is consulted
/// before strategy dispatch: a correction the operator set from the
/// dashboard decides the binary's classification, with no CLI re-run.
/// When no shared handle is passed (a plain CLI classify), one is opened
/// over the workspace so persisted overrides are honored there too.
pub async fn handle_classify(
    dlls: &[String],
    target_dir: &Path,
    workspace: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
    classification_overrides: Option<&ClassificationOverrideControl>,
) -> Result<()> {
    info!(count = dlls.len(), "Classifying DLLs");

    // Kuna is the only analysis engine (issue #214): the analyzer reads
    // through the seam. The classification counts themselves come from PE
    // headers on disk. The primary DLL is loaded in-process so the
    // analyzer has a live source for any analysis-engine read it needs.
    let primary = dlls.first().map(String::as_str).unwrap_or("classify");
    let kuna = load_kuna_at(settings, &target_dir.join(primary))?;

    // Initialize analyzer
    let api_mappings = ApiMappings::default();
    let overrides = override_handle_or_open(classification_overrides, workspace)?;
    let analyzer = Analyzer::new(calxgloss_decomp::PipelineSource::from(kuna), api_mappings)
        .with_classification_overrides(overrides);

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
                classification_strategy: format!("{:?}", c.strategy),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_corrupt_override_document_stops_the_classify_open_naming_the_fault() {
        // The classify path opens the persisted override document
        // itself when no live handle stands: corrupt bytes stop the
        // command naming the document (issue #459).
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let analysis = dir.path().join("re").join("analysis");
        std::fs::create_dir_all(&analysis).expect("analysis dir");
        std::fs::write(analysis.join("classification_overrides.json"), "{ not json")
            .expect("corrupt the override document");

        let err = override_handle_or_open(None, dir.path())
            .expect_err("a corrupt document stops the open");
        let message = format!("{err:#}");
        assert!(
            message.contains("classification_overrides.json"),
            "the fault names the unreadable document: {message}"
        );
    }

    #[test]
    fn a_workspace_with_no_override_document_opens_the_clean_handle() {
        // A never-filed document is the clean un-overridden state —
        // the command runs with nothing overridden (issue #459).
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let control =
            override_handle_or_open(None, dir.path()).expect("missing is the clean state");
        assert!(control.records().overrides.is_empty());
    }

    #[test]
    fn a_passed_live_handle_is_used_as_is() {
        // A running server's handle carries the live overrides; the
        // classify path never re-opens the document underneath it.
        let control = ClassificationOverrideControl::new();
        let chosen = override_handle_or_open(Some(&control), Path::new("/nonexistent"))
            .expect("the live handle is used as is");
        assert_eq!(chosen.records().overrides, control.records().overrides);
    }
}
