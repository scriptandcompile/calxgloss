//! End-to-end shim generation pipeline.
//!
//! This module orchestrates the full shim generation flow triggered by DLL
//! classification: generate mappings → generate source → generate tests →
//! verify → persist results.
//!
//! # Flow
//!
//! 1. [`generate_shim_mappings`] produces a [`ShimLayer`] from the DLL's
//!    exports and the LLM.
//! 2. [`generate_shim_source`] creates Rust source code from the mappings.
//! 3. [`generate_shim_tests`] creates a test module for the shim.
//! 4. [`Verifier::verify_shim`] compiles and tests the shim in a sandboxed
//!    scratch project.
//! 5. All artifacts are persisted to `re/shims/<dll_name>/` on disk.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::shim_pipeline::{ShimPipeline, ShimPipelineResult};
//! use calxgloss_llm::LlmClient;
//! use calxgloss_types::Export;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
//! let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let verifier = calxgloss_verify::Verifier::new(std::path::Path::new("/tmp/calxgloss-work"))?;
//! let exports = Vec::<Export>::new();
//!
//! let pipeline = ShimPipeline::new(
//!     "d3d9.dll".to_string(),
//!     "wgpu".to_string(),
//!     exports,
//!     llm,
//!     verifier,
//! );
//!
//! let result = pipeline.run(
//!     std::path::Path::new("/path/to/workspace"),
//!     true,  // skip_git
//!     None,  // git manager
//! ).await?;
//!
//! println!("Generated {} mappings", result.mapping_count);
//! println!("Verification passed: {}", result.verification.all_passed());
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};

use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::LlmClient;
use calxgloss_types::{Export, ShimLayer, ShimVerificationResult};
use tracing::{error, info, instrument, warn};

use crate::shim::generate_shim_mappings;
use crate::shim_gen::{ShimGenerationMode, generate_shim_source};
use crate::shim_test_gen::generate_shim_tests;

use calxgloss_verify::Verifier;

/// Convert a Ghidra [`Symbol`] into a calxgloss [`Export`].
///
/// Ghidra symbols carry `(name, address, imported)` while the shim pipeline
/// needs `(name, address, signature)`. Since shim mappings are produced by the
/// LLM (which can infer signatures from context), the signature is left empty
/// and will be filled in by the LLM if needed.
fn symbol_to_export(sym: &calxgloss_ghidra::Symbol) -> Export {
    Export {
        name: sym.name.clone(),
        address: sym.address,
        signature: String::new(),
    }
}

/// Artifacts produced by a single shim pipeline run.
///
/// Contains the generated [`ShimLayer`], verification results, and paths
/// to all persisted files.
#[derive(Debug, Clone)]
pub struct ShimPipelineResult {
    /// The generated shim layer with all API mappings.
    pub shim: ShimLayer,
    /// Verification results from compiling and testing the shim.
    pub verification: ShimVerificationResult,
    /// Path to the persisted mappings JSON file.
    pub mappings_path: PathBuf,
    /// Path to the persisted shim source file.
    pub source_path: PathBuf,
    /// Path to the persisted shim tests file.
    pub tests_path: PathBuf,
    /// Path to the persisted verification result file.
    pub verification_path: PathBuf,
    /// Total number of API mappings generated.
    pub mapping_count: usize,
}

/// Errors that can occur during the shim pipeline.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("LLM mapping generation failed: {0}")]
    MappingGeneration(#[source] calxgloss_llm::LlmError),

    #[error("Source code generation failed: {0}")]
    SourceGeneration(String),

    #[error("Verification failed: {0}")]
    Verification(#[source] anyhow::Error),

    #[error("Persistence failed: {0}")]
    Persistence(#[source] std::io::Error),
}

/// Orchestrates the end-to-end shim generation flow for a single DLL.
///
/// The pipeline executes the following steps:
///
/// 1. **Generate mappings** — Send the DLL's exports to the LLM, which returns
///    a mapping table translating each exported function to a target crate API.
/// 2. **Generate source** — Produce Rust source code implementing the shim layer
///    from the mapping table.
/// 3. **Generate tests** — Produce a Rust test module that verifies each mapping.
/// 4. **Verify** — Scaffold a sandboxed Cargo project, compile the shim, and
///    run the tests.
/// 5. **Persist** — Write all artifacts to `re/shims/<dll_name>/` on disk.
pub struct ShimPipeline {
    /// The original DLL filename (e.g., `"d3d9.dll"`).
    dll_name: String,
    /// The target Rust crate name (e.g., `"wgpu"`).
    target_crate: String,
    /// The DLL's exported functions.
    exports: Vec<Export>,
    /// The LLM client for mapping generation.
    llm: LlmClient,
    /// The verifier for compilation and test execution.
    verifier: Verifier,
}

impl ShimPipeline {
    /// Creates a new shim pipeline for the given DLL.
    ///
    /// # Arguments
    ///
    /// * `dll_name` — The original DLL filename.
    /// * `target_crate` — The Rust crate that replaces the DLL.
    /// * `exports` — The DLL's exported functions.
    /// * `llm` — The LLM client for mapping generation.
    /// * `verifier` — The verifier for compilation and test execution.
    pub fn new(
        dll_name: String,
        target_crate: String,
        exports: Vec<Export>,
        llm: LlmClient,
        verifier: Verifier,
    ) -> Self {
        Self {
            dll_name,
            target_crate,
            exports,
            llm,
            verifier,
        }
    }

    /// Runs the full pipeline and persists all artifacts to the given base directory.
    ///
    /// # Arguments
    ///
    /// * `base_dir` — The workspace root directory. Artifacts are written to
    ///   `<base_dir>/re/shims/<dll_name>/`.
    /// * `skip_git` — If `true`, skip git commit of the generated artifacts.
    ///
    /// # Returns
    ///
    /// A [`ShimPipelineResult`] containing the generated shim, verification
    /// results, and file paths on success.
    ///
    /// On mapping generation failure, the pipeline produces a skeletal shim
    /// (with `TODO` stubs) and returns the best-effort result so the
    /// reviewer can still inspect and fix the output.
    #[instrument(skip(self, base_dir, git), fields(dll = %self.dll_name, crate = %self.target_crate))]
    pub async fn run(
        &self,
        base_dir: &Path,
        skip_git: bool,
        git: Option<&calxgloss_git::GitManager>,
    ) -> Result<ShimPipelineResult, PipelineError> {
        let dll_dir = base_dir.join("re").join("shims").join(&self.dll_name);
        std::fs::create_dir_all(&dll_dir).map_err(PipelineError::Persistence)?;

        let mappings_path = dll_dir.join("mappings.json");
        let source_path = dll_dir.join("shim.rs");
        let tests_path = dll_dir.join("shim_tests.rs");
        let verification_path = dll_dir.join("verification.json");

        // Step 1: Generate mappings via LLM.
        let shim = match generate_shim_mappings(
            &self.dll_name,
            &self.target_crate,
            &self.exports,
            &self.llm,
        )
        .await
        {
            Ok(s) => {
                info!(mappings = s.mapping_count(), "LLM generated shim mappings");
                s
            }
            Err(e) => {
                warn!(error = %e, "LLM mapping generation failed, falling back to skeletal shim");

                // On failure, produce a skeletal shim with the DLL/crate info
                // but no actual mappings. The reviewer can regenerate mappings
                // or manually create them.
                ShimLayer::new(self.dll_name.clone(), self.target_crate.clone())
            }
        };

        // Step 2: Generate source code.
        let source = generate_shim_source(&shim, ShimGenerationMode::Complete);
        if source.is_empty() {
            return Err(PipelineError::SourceGeneration(
                "Generated source code is empty".to_string(),
            ));
        }

        // Step 3: Generate tests.
        let tests = generate_shim_tests(&shim);

        // Step 4: Verify the shim (compile + test).
        // Only verify if there are actual mappings to test.
        let verification_result = if shim.mapping_count() > 0 {
            self.verifier
                .verify_shim(&source, &tests, &self.target_crate, &self.dll_name)
                .await
                .map_err(PipelineError::Verification)
        } else {
            info!("No mappings to verify (skeletal shim)");
            Ok(ShimVerificationResult {
                compiled: true,
                compilation_errors: Vec::new(),
                compilation_warnings: Vec::new(),
                tests_passed: 0,
                tests_total: 0,
                edge_tests_passed: 0,
                edge_tests_total: 0,
                failed_tests: Vec::new(),
                mapping_results: Vec::new(),
            })
        };

        // Summarize verification results.
        if let Ok(ref vr) = verification_result {
            if vr.all_passed() {
                info!(
                    tests_passed = vr.total_passed(),
                    tests_total = vr.total_tests(),
                    "Shim verification passed all tests"
                );
            } else if vr.compiled {
                warn!(
                    tests_passed = vr.total_passed(),
                    tests_total = vr.total_tests(),
                    "Shim compiled but some tests failed"
                );
            } else {
                error!(
                    error_count = vr.compilation_errors.len(),
                    "Shim failed to compile"
                );
            }
        }

        // Step 5: Persist all artifacts.
        // Always persist, even if verification errored (use placeholder).
        let vr_for_persist: ShimVerificationResult = match &verification_result {
            Ok(vr) => vr.clone(),
            Err(_) => ShimVerificationResult {
                compiled: false,
                compilation_errors: Vec::new(),
                compilation_warnings: Vec::new(),
                tests_passed: 0,
                tests_total: 0,
                edge_tests_passed: 0,
                edge_tests_total: 0,
                failed_tests: Vec::new(),
                mapping_results: Vec::new(),
            },
        };
        persist_shim_artifacts(
            &shim,
            &source,
            &tests,
            &vr_for_persist,
            &mappings_path,
            &source_path,
            &tests_path,
            &verification_path,
        )
        .map_err(PipelineError::Persistence)?;

        // Git commit (if not skipped).
        if !skip_git && let Some(git) = git {
            let files = [
                mappings_path.to_string_lossy().to_string(),
                source_path.to_string_lossy().to_string(),
                tests_path.to_string_lossy().to_string(),
                verification_path.to_string_lossy().to_string(),
            ];
            let commit_msg = format!(
                "shim: generate {} layer for {} ({} mappings)",
                self.target_crate,
                self.dll_name,
                shim.mapping_count()
            );

            if let Err(e) = git.commit_to_main(&commit_msg, &files) {
                warn!(error = %e, "Failed to commit shim artifacts to git");
            }
        }

        let mapping_count = shim.mapping_count();

        Ok(ShimPipelineResult {
            shim,
            verification: verification_result.unwrap_or_else(|e| ShimVerificationResult {
                compiled: false,
                compilation_errors: vec![e.to_string()],
                compilation_warnings: Vec::new(),
                tests_passed: 0,
                tests_total: 0,
                edge_tests_passed: 0,
                edge_tests_total: 0,
                failed_tests: Vec::new(),
                mapping_results: Vec::new(),
            }),
            mappings_path,
            source_path,
            tests_path,
            verification_path,
            mapping_count,
        })
    }
}

/// Persist all shim artifacts to disk.
///
/// Writes four files:
/// - `mappings.json` — the LLM-generated [`ShimLayer`] as JSON
/// - `shim.rs` — the generated Rust source code
/// - `shim_tests.rs` — the generated Rust test module
/// - `verification.json` — the verification results as JSON
#[allow(clippy::too_many_arguments)]
fn persist_shim_artifacts(
    shim: &ShimLayer,
    source: &str,
    tests: &str,
    verification: &ShimVerificationResult,
    mappings_path: &Path,
    source_path: &Path,
    tests_path: &Path,
    verification_path: &Path,
) -> std::result::Result<(), std::io::Error> {
    // Persist mappings.
    let mappings_json = serde_json::to_string_pretty(shim)
        .map_err(|e| std::io::Error::other(format!("Failed to serialize shim mappings: {e}")))?;
    std::fs::write(mappings_path, &mappings_json)?;
    info!(path = %mappings_path.display(), "Persisted shim mappings");

    // Persist source.
    std::fs::write(source_path, source)?;
    info!(path = %source_path.display(), "Persisted shim source");

    // Persist tests.
    std::fs::write(tests_path, tests)?;
    info!(path = %tests_path.display(), "Persisted shim tests");

    // Persist verification results.
    let verification_json = serde_json::to_string_pretty(verification).map_err(|e| {
        std::io::Error::other(format!("Failed to serialize verification results: {e}"))
    })?;
    std::fs::write(verification_path, &verification_json)?;
    info!(path = %verification_path.display(), "Persisted verification results");

    Ok(())
}

/// Run the shim pipeline for all crate-replacement DLLs in the given
/// classification list.
///
/// Fetches exports from Ghidra for each DLL, then runs the full
/// generation → verify → persist pipeline.
///
/// # Arguments
///
/// * `classifications` — DLL classifications to process (filtered to
///   `CrateReplacement` strategy).
/// * `ghidra` — Ghidra client for fetching export symbols.
/// * `llm` — LLM client for mapping generation.
/// * `verifier` — Verifier for compilation and test execution.
/// * `base_dir` — Workspace root for artifact persistence.
/// * `skip_git` — If `true`, skip git commit of the generated artifacts.
/// * `git` — Optional git manager for committing artifacts.
///
/// # Returns
///
/// A vector of [`ShimPipelineResult`] — one per DLL. Failed
/// DLLs produce an error entry that can be retried individually.
pub async fn generate_all_shims(
    classifications: &[crate::DllClassification],
    ghidra: &GhidraClient,
    llm: LlmClient,
    verifier: Verifier,
    base_dir: &Path,
    skip_git: bool,
    git: Option<&calxgloss_git::GitManager>,
) -> Vec<Result<ShimPipelineResult, PipelineError>> {
    let shim_layers: Vec<_> = classifications
        .iter()
        .filter(|c| matches!(c.strategy, crate::Strategy::CrateReplacement { .. }))
        .collect();

    info!(
        count = shim_layers.len(),
        "Starting auto-shim pipeline for {} crate-replacement DLL(s)",
        shim_layers.len()
    );

    let mut results = Vec::with_capacity(shim_layers.len());

    for classification in shim_layers {
        let dll_name = &classification.dll;
        let crate_name = classification
            .crate_replacement
            .as_deref()
            .unwrap_or("<unknown>");

        info!(dll = %dll_name, crate = crate_name, "Processing shim for DLL");

        // Fetch exports from Ghidra.
        // GhidraMCP serves the currently open program, so we fetch all exports
        // and let the LLM filter by context hints.
        let symbols = ghidra.exports(None).await;

        let exports: Vec<Export> = match &symbols {
            Ok(syms) => syms.iter().map(symbol_to_export).collect(),
            Err(e) => {
                warn!(dll = %dll_name, error = %e, "Failed to fetch exports from Ghidra; using empty list");
                Vec::new()
            }
        };

        let pipeline = ShimPipeline::new(
            dll_name.clone(),
            crate_name.to_string(),
            exports,
            llm.clone(),
            verifier.clone(),
        );
        let result = pipeline.run(base_dir, skip_git, git).await;
        results.push(result);
    }

    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.len() - successes;

    info!(successes, failures, "Auto-shim pipeline complete");

    results
}
