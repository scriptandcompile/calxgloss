//! The `auto-shim` command — generate shim layers for crate-replacement DLLs.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_analysis::Analyzer;
use calxgloss_analysis::shim_pipeline;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::GitManager;
use calxgloss_llm::LlmClient;
use calxgloss_pal::ApiMappings;
use calxgloss_verify::Verifier;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// Handle the `auto-shim` subcommand: generate shim layers for crate-replacement DLLs.
pub async fn handle_auto_shim(
    dll_filter: Option<&str>,
    skip_git: bool,
    _target_dir: &Path,
    repo_dir: &Path,
    settings: &Settings,
) -> Result<()> {
    info!("Starting auto-shim pipeline");

    // Initialize Ghidra client.
    let ghidra_url = &settings.ghidra_url.value;
    let mut ghidra_config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;

    if let Some(key) = &settings.ghidra_api_key {
        ghidra_config = ghidra_config.with_api_key(key.value.clone());
    }

    let ghidra = GhidraClient::from_config(ghidra_config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize LLM client.
    let llm_url = settings
        .llm_url
        .as_ref()
        .context("LLM URL not configured")?
        .value
        .as_str();
    let llm_model = settings
        .llm_model
        .as_ref()
        .context("LLM model not configured")?
        .value
        .as_str();
    let llm = LlmClient::from_url(llm_url, llm_model)
        .with_context(|| format!("Failed to initialize LLM client at {}", llm_url))?;

    // Initialize analyzer for classification reading.
    let api_mappings = ApiMappings::default();
    let analyzer = Analyzer::new(ghidra.clone(), api_mappings);

    // Determine which DLLs to process.
    let (dll_names, classifications): (Vec<String>, Vec<calxgloss_analysis::DllClassification>) =
        if let Some(dll) = dll_filter {
            // Process a single specified DLL.
            let classification = analyzer.classify_dll(dll).await?;
            let names: Vec<String> = vec![dll.to_string()];
            (names, vec![classification])
        } else {
            // Read existing classification records to find CrateReplacement DLLs.
            let classify_dir = repo_dir.join("re").join("classify");
            if !classify_dir.exists() {
                anyhow::bail!(
                    "No classification records found at {}. Run `classify` first.",
                    classify_dir.display()
                );
            }

            let mut names: Vec<String> = Vec::new();
            let mut classif = Vec::new();

            for entry in std::fs::read_dir(&classify_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    let json = std::fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {}", path.display()))?;
                    let c: calxgloss_analysis::DllClassification = serde_json::from_str(&json)
                        .with_context(|| {
                            format!("Failed to parse classification record: {}", path.display())
                        })?;

                    if matches!(
                        c.strategy,
                        calxgloss_analysis::Strategy::CrateReplacement { .. }
                    ) {
                        names.push(c.dll.clone());
                        classif.push(c);
                    }
                }
            }

            if names.is_empty() {
                println!(
                    "  {} No crate-replacement DLLs found in classification records.",
                    yellow_bold("!")
                );
                println!();
                println_content(
                    "Run `classify --dll <dll1> <dll2> ...` to produce crate-replacement candidates.",
                );
                return Ok(());
            }

            (names, classif)
        };

    info!(count = dll_names.len(), dlls = ?dll_names, "Auto-shim targets");

    // Initialize verifier.
    let verifier = Verifier::new(repo_dir).context("Failed to create verifier")?;

    // Initialize git manager if not skipped.
    let git_manager = if !skip_git {
        GitManager::open(repo_dir).ok()
    } else {
        None
    };

    // Run the auto-shim pipeline.
    let results = shim_pipeline::generate_all_shims(
        &classifications,
        &ghidra,
        llm,
        verifier,
        repo_dir,
        skip_git,
        git_manager.as_ref(),
    )
    .await;

    // Summarize results.
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.len() - successes;

    println!();
    println!(
        "  {} Auto-shim pipeline complete",
        if failures == 0 {
            green_bold("✓")
        } else {
            yellow_bold("!")
        }
    );
    println!();
    println!(
        "  {} {} succeeded, {} failed",
        if failures == 0 { "✓" } else { "!" },
        successes,
        failures
    );
    println!();

    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(pipeline_result) => {
                info!(
                    dll = %pipeline_result.shim.source_dll,
                    mappings = pipeline_result.mapping_count,
                    "Shim generated successfully"
                );
                let verify_status = if pipeline_result.verification.all_passed() {
                    "passed".to_string()
                } else if pipeline_result.verification.compiled {
                    "partial".to_string()
                } else {
                    "failed".to_string()
                };
                println!(
                    "  {} {} → {} ({} mappings, verification: {})",
                    green_bold("✓"),
                    dll_names[i],
                    pipeline_result.shim.target_crate,
                    pipeline_result.mapping_count,
                    verify_status,
                );
            }
            Err(e) => {
                warn!(error = %e, "Shim pipeline failed");
                let msg: String = e.to_string().chars().take(60).collect();
                println!("  {} {} → {}", red_bold("✗"), dll_names[i], msg);
            }
        }
    }

    println!();
    info!(count = dll_names.len(), "Auto-shim complete");
    Ok(())
}
