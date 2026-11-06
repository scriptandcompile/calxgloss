//! The [`Verifier`] engine and [`CompileResult`] — core verification types.

use anyhow::{Context, Result};
use calxgloss_types::{
    BinaryIdentity, DimensionCounts, PersistError, ShimVerificationResult, TestCase, UnknownKind,
    UnknownLedger, UnknownOrigin, UnknownRecord, UnknownResolutions, UnknownSeverity,
    VerificationReceipt, VerificationResult, VerificationVerdict, VerifierCommand, persist,
    scan::now_unix_secs, unknown_ledger_path, unknown_resolutions_path,
    verification_receipt_markdown, verification_receipt_path,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::cargo;
use crate::helpers::{sanitize_crate_name, sanitize_identifier};
use crate::parse;

/// Shared PAL stub content, embedded at compile time from `src/pal/src/stub_content.rs`.
///
/// This file mirrors the stubs in `stubs.rs`.  The constant is written to
/// `scratch/pal/src/stub_content.rs` when the first scratch project is
/// created (and re-written whenever the embedded template has changed), so
/// the scratch project can `include!` it — which is why it must not carry
/// `//!` doc comments (E0753 inside a macro expansion).
pub const PAL_STUB_CONTENT: &str = include_str!("pal/src/stub_content.rs");

// ============================================================
// Public API
// ============================================================

/// Verification engine for translated Rust code.
///
/// Takes Rust source code and baseline test cases, creates a sandboxed
/// compilation environment, and verifies that the translated code compiles
/// and produces behavior matching the original binary.
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Working directory for scratch Cargo projects.
    work_dir: PathBuf,
}

/// Result of the compilation step.
#[derive(Debug, Clone)]
pub struct CompileResult {
    /// Whether the code compiled without errors.
    pub success: bool,

    /// Compilation error messages, if any.
    pub errors: Vec<String>,

    /// Compilation warnings, if any.
    pub warnings: Vec<String>,

    /// Raw compiler output for debugging.
    pub output: String,
}

/// What the calling seam knows about one verify run that the verifier
/// itself cannot: its place in the retry sequence and where the baseline
/// suite was read from. These ride the filed *verification receipt* so
/// the record names the story behind the verdict, not just the verdict.
///
/// Every field has a standalone default — attempt 1, no strategy, manual
/// path, no filed baseline file — which is exactly what a one-off `verify`
/// command run outside a retry loop is.
#[derive(Debug, Clone)]
pub struct VerifyContext<'a> {
    /// The 1-based attempt number this run judges, keying the filed
    /// receipt file.
    pub attempt: u32,

    /// The strategy that produced the code under verification
    /// (`"initial"`, `"compile_fix"`, …).
    pub retry_strategy: &'a str,

    /// The shape of the prompt the attempt took, as the retry seam
    /// names it.
    pub attempt_path: &'a str,

    /// Where the baseline suite was read from, when a filed baseline
    /// document existed — the location rides the suite digest fold.
    pub baseline_file: Option<&'a Path>,
}

impl Default for VerifyContext<'_> {
    fn default() -> Self {
        Self {
            attempt: 1,
            retry_strategy: "standalone",
            attempt_path: "manual",
            baseline_file: None,
        }
    }
}

/// One verify run handed back to its caller: the gate's judgement beside
/// the *verification receipt* the run filed, so the commit site can
/// stage the pair onto its branch without re-reading the record tree.
#[derive(Debug, Clone)]
pub struct VerificationRun {
    /// The gate's judgement — compilation status, test counts, detailed
    /// divergences (see [`VerificationResult`]).
    pub result: VerificationResult,

    /// The receipt exactly as filed, digest included.
    pub receipt: VerificationReceipt,
}

impl Verifier {
    /// Create a new verifier with the given working directory.
    ///
    /// The working directory is used to store scratch Cargo projects
    /// created during verification. The directory is created if it
    /// does not exist.
    #[instrument(skip(work_dir))]
    pub fn new(work_dir: &Path) -> Result<Self> {
        let work_dir = work_dir.to_path_buf();
        std::fs::create_dir_all(&work_dir)
            .context("Failed to create verifier working directory")?;
        info!(work_dir = %work_dir.display(), "Created verifier");
        Ok(Self { work_dir })
    }

    /// Compile the translated Rust code.
    ///
    /// Scaffolds a minimal Cargo project, writes the translated code
    /// as a library module with stub implementations for external
    /// dependencies, and runs `cargo check`.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL name (used for project identification).
    /// * `function` — The function name (used for module naming).
    /// * `rust_code` — The translated Rust source code.
    ///
    /// # Returns
    ///
    /// A [`CompileResult`] with compilation status and error details.
    #[instrument(skip(self, rust_code), fields(binary, function))]
    pub async fn compile(
        &self,
        binary: &str,
        function: &str,
        rust_code: &str,
    ) -> Result<CompileResult> {
        debug!(binary, function, "Starting compilation check");

        let project = self.scaffold_project(binary, function, rust_code)?;
        let output = cargo::run_cargo_check(&project)
            .await
            .context("cargo check failed")?;
        let (success, errors, warnings) = parse::parse_cargo_output(&output);

        if success {
            info!(binary, function, "Compilation successful");
        } else {
            error!(
                binary,
                function,
                error_count = errors.len(),
                "Compilation failed"
            );
        }

        Ok(CompileResult {
            success,
            errors,
            warnings,
            output,
        })
    }

    /// Verify the translated Rust code against baseline tests, file its
    /// *verification receipt* pair, and hand the run back.
    ///
    /// Full verification flow:
    /// 1. Compile the code via `cargo check`
    /// 2. If compilation succeeds, run behavioral tests against baseline inputs
    /// 3. Compare outputs against baseline expected values
    /// 4. File the receipt pair — the JSON authority plus its Markdown twin,
    ///    paired by content digest — under the record convention beside
    ///    `re/baseline/` (the verifier owns its own receipt, ADR-0053)
    ///
    /// Every run files a pair, pass or fail: the `passed`, `tests-failed`,
    /// and `compile-failed` verdicts each leave their record. Filed pairs
    /// are never edited in place — a later run writes its own. A run whose
    /// verifier toolchain itself breaks is a harness failure: it files its
    /// pair verdicted `harness-error` and records no unit verdict — the
    /// unit was never judged, so the seam answers with `Err`, never with a
    /// `VerificationResult` (P25.6, issue #415). A pair that cannot be
    /// written files an admitted unknown naming the run it belongs to;
    /// the run's own verdict still stands, honestly degraded, and the
    /// missing authority is never fabricated into a unit verdict or
    /// dropped as a log line.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL name.
    /// * `function` — The function name.
    /// * `rust_code` — The translated Rust source code.
    /// * `baseline_tests` — Baseline test cases with expected return values.
    /// * `context` — The run's place in the retry sequence and where the
    ///    baseline suite was read from, as the calling seam knows them.
    ///
    /// # Returns
    ///
    /// A [`VerificationRun`] carrying the [`VerificationResult`] (compilation
    /// status, test pass/fail counts, detailed failure information) beside
    /// the [`VerificationReceipt`] the run filed, so commit sites can stage it.
    #[instrument(skip(self, rust_code, baseline_tests, context), fields(binary, function, test_count = baseline_tests.len()))]
    pub async fn verify(
        &self,
        binary: &str,
        function: &str,
        rust_code: &str,
        baseline_tests: &[TestCase],
        context: &VerifyContext<'_>,
    ) -> Result<VerificationRun> {
        debug!(binary, function, "Starting verification");

        let started = Instant::now();
        let suite_digest = match self.suite_digest(baseline_tests, context) {
            Ok(digest) => digest,
            Err(e) => {
                // The suite itself will not fold: no receipt can name a
                // suite digest, so the run files its unknown and the fold
                // error stands — loudly, never a silent skip. If even the
                // unknown cannot be filed, both failures ride one error.
                if let Err(unknown) = self.file_unfiled_receipt_unknown(
                    binary,
                    function,
                    context.attempt,
                    &format!("the baseline suite digest could not be folded: {e}"),
                ) {
                    return Err(anyhow::anyhow!(
                        "the baseline suite digest could not be folded: {e}; and the \
                         admitted unknown for the unfiled receipt could not be filed: {unknown:#}"
                    ));
                }
                return Err(e);
            }
        };
        let compile_result = match self.compile(binary, function, rust_code).await {
            Ok(result) => result,
            Err(e) => {
                // The compile leg itself broke — a scaffold or cargo that
                // could not even be run. The verifier's own failure, never
                // the unit's: the run files its pair verdicted
                // `harness-error` and hands the error back, with no
                // verdict and no unit judgement claimed.
                match self.file_harness_error_receipt(
                    binary,
                    function,
                    context,
                    &suite_digest,
                    &format!("the compile leg broke: {e}"),
                    started.elapsed().as_millis() as u64,
                    0,
                ) {
                    Ok(()) => return Err(e),
                    // The honesty filing failed on top of the harness failure:
                    // chain both, never losing the harness error itself.
                    Err(honesty) => return Err(harness_fault(e, honesty)),
                }
            }
        };
        let compile_ms = started.elapsed().as_millis() as u64;

        // A compile-failed gate never runs its test leg, so its test-run
        // timing stays zero — the receipt reads the gate's shape off the
        // timings too.
        let mut test_run_ms = 0u64;
        let result = if !compile_result.success {
            info!(binary, function, "Skipping tests — compilation failed");
            unrun_suite_result(compile_result.errors)
        } else {
            info!(
                binary,
                function, "Compilation passed, running behavioral tests"
            );

            let test_started = Instant::now();
            let project =
                match self.scaffold_test_project(binary, function, rust_code, baseline_tests) {
                    Ok(project) => project,
                    Err(e) => {
                        // The test project could not even be scaffolded: the
                        // test leg broke inside the verifier, so the run is a
                        // harness failure — pair verdicted `harness-error`,
                        // no verdict handed back.
                        match self.file_harness_error_receipt(
                            binary,
                            function,
                            context,
                            &suite_digest,
                            &format!("the test project could not be scaffolded: {e}"),
                            compile_ms,
                            test_started.elapsed().as_millis() as u64,
                        ) {
                            Ok(()) => return Err(e),
                            // Chain both failures; the harness error is never lost.
                            Err(honesty) => return Err(harness_fault(e, honesty)),
                        }
                    }
                };
            let test_output = match cargo::run_test_runner(&project).await {
                Ok(output) => output,
                Err(e) => {
                    // A runner that never started assessed nothing. The
                    // old fallback text ("Test execution failed: …")
                    // filed that as a zero-test run a reader could
                    // almost mistake for a clean verdict. That swallow
                    // is gone: an unstartable runner is a harness failure.
                    match self.file_harness_error_receipt(
                        binary,
                        function,
                        context,
                        &suite_digest,
                        &format!("the test runner could not be started: {e}"),
                        compile_ms,
                        test_started.elapsed().as_millis() as u64,
                    ) {
                        Ok(()) => return Err(e),
                        // Chain both failures; the harness error is never lost.
                        Err(honesty) => return Err(harness_fault(e, honesty)),
                    }
                }
            };
            test_run_ms = test_started.elapsed().as_millis() as u64;

            let report = parse::parse_test_results(&test_output, baseline_tests);
            if !report.produced_results && !baseline_tests.is_empty() {
                // The suite had cases and the runner printed no result
                // rows at all. Three honest readings: the *test project* —
                // the unit beside the generated runner — never built,
                // which is where a unit that does not match the harness's
                // calling shape surfaces as its own compile failure; the
                // unit itself crashed the runner before it printed, which
                // is a test that failed with an unobserved return; or the
                // runner broke without a word, which is the verifier's
                // failure, never the unit's (#415's rule).
                if test_output.contains("could not compile") {
                    let (_, errors, _) = parse::parse_cargo_output(&test_output);
                    info!(
                        binary,
                        function, "Test project did not compile — tests never ran"
                    );
                    unrun_suite_result(errors)
                } else if parse::runner_death_signal(&test_output) {
                    warn!(
                        binary,
                        function, "Unit crashed the runner before it printed a result"
                    );
                    VerificationResult {
                        compiled: true,
                        compilation_errors: Vec::new(),
                        tests_passed: 0,
                        tests_total: baseline_tests.len(),
                        // The runner printed nothing, so no printed row
                        // says *which* case it died on: the record names
                        // the crash and claims no inputs and no return.
                        failed_tests: vec![parse::runner_died_before_first_row()],
                        trace_assessed_tests: 0,
                        value_assessed_tests: 0,
                        values_matched_tests: 0,
                    }
                } else {
                    match self.file_harness_error_receipt(
                        binary,
                        function,
                        context,
                        &suite_digest,
                        "the test runner produced no result rows",
                        compile_ms,
                        test_started.elapsed().as_millis() as u64,
                    ) {
                        Ok(()) => {
                            return Err(anyhow::anyhow!(
                                "the test runner produced no result rows for {function} \
                                 in {binary}"
                            ));
                        }
                        // Chain both failures; the harness error is never lost.
                        Err(honesty) => {
                            return Err(harness_fault(
                                anyhow::anyhow!(
                                    "the test runner produced no result rows for {function} \
                                     in {binary}"
                                ),
                                honesty,
                            ));
                        }
                    }
                }
            } else if report.incomplete {
                // The runner died part-way: the unit crashed on one of its
                // own cases. Name the crashed case and leave its return
                // unobserved — a failing test, never a broken harness.
                let crash_index = report.total;
                let crash_inputs = baseline_tests
                    .get(crash_index)
                    .map(|case| case.inputs.clone())
                    .unwrap_or(serde_json::Value::Null);
                let mut failed = report.failed;
                failed.push(parse::crashed_suite_failure(crash_index, &crash_inputs));
                warn!(
                    binary,
                    function,
                    crashed_at = crash_index,
                    suite_len = baseline_tests.len(),
                    "Unit crashed the runner part-way through the suite"
                );
                VerificationResult {
                    compiled: true,
                    compilation_errors: Vec::new(),
                    tests_passed: report.passed,
                    tests_total: baseline_tests.len(),
                    failed_tests: failed,
                    trace_assessed_tests: report.trace_assessed,
                    value_assessed_tests: report.value_assessed,
                    values_matched_tests: report.values_matched,
                }
            } else {
                info!(
                    binary,
                    function,
                    passed = report.passed,
                    total = report.total,
                    trace_assessed = report.trace_assessed,
                    value_assessed = report.value_assessed,
                    "Verification complete"
                );

                VerificationResult {
                    compiled: true,
                    compilation_errors: Vec::new(),
                    tests_passed: report.passed,
                    tests_total: report.total,
                    failed_tests: report.failed,
                    trace_assessed_tests: report.trace_assessed,
                    value_assessed_tests: report.value_assessed,
                    values_matched_tests: report.values_matched,
                }
            }
        };

        // The verifier owns its own receipt: fold it, file the digest-
        // paired JSON+Markdown pair, and hand it back beside the result.
        let receipt = self.file_receipt(
            &result,
            binary,
            function,
            baseline_tests,
            context,
            compile_ms,
            test_run_ms,
        )?;
        Ok(VerificationRun { result, receipt })
    }

    /// Fold and file one run's *verification receipt* pair: the JSON
    /// authority under the record convention plus its Markdown twin,
    /// paired by content digest. Filed pairs are never edited in place —
    /// a later attempt writes its own name beside the earlier one.
    ///
    /// Returns the receipt exactly as filed, so the caller holds the same
    /// document that stands on disk (and can stage it onto its branch).
    // The run's facts are passed positionally — result, unit identity,
    // suite, place-in-sequence, and the two timings — same shape as the
    // retry ladder's recording helpers.
    #[allow(clippy::too_many_arguments)]
    fn file_receipt(
        &self,
        result: &VerificationResult,
        binary: &str,
        function: &str,
        baseline_tests: &[TestCase],
        context: &VerifyContext<'_>,
        compile_ms: u64,
        test_run_ms: u64,
    ) -> Result<VerificationReceipt> {
        // The verdict is the run's own, never a later reader's reading:
        // a unit that never compiled is nobody's test failure, and a
        // green gate with nobody asking still ran only the compile leg.
        let verdict = if !result.compiled {
            VerificationVerdict::CompileFailed
        } else if result.failed_tests.is_empty() {
            VerificationVerdict::Passed
        } else {
            VerificationVerdict::TestsFailed
        };
        // The gate's breadth is what was *actually invoked*: a unit that
        // never compiled never ran a baseline case, and a zero-case suite
        // runs no case through the runner — either one reads compile-only
        // so a reviewer never mistakes a narrow gate for the full one.
        let verifier_command = if result.compiled && !baseline_tests.is_empty() {
            VerifierCommand::CompileAndBaselineTest
        } else {
            VerifierCommand::CompileOnly
        };

        // The dimension map mirrors the returned result's facts, taken
        // straight from the runner's own per-case assessments rather than
        // reconstructed from the pass verdict: the values dimension counts
        // only cases the runner could call *and* hold against an expected
        // return, and the trace dimension counts only cases the capture
        // vocabulary could speak an expectation for (ADR-0057's honesty
        // rule: unassessed never reads as passed).
        let trace_failed = result
            .failed_tests
            .iter()
            .filter(|f| !f.expected_api_calls.is_empty() && f.trace_divergence_index.is_some())
            .count();
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "values".to_string(),
            DimensionCounts {
                assessed: result.value_assessed_tests,
                passed: result.values_matched_tests,
            },
        );
        dimensions.insert(
            "api_trace".to_string(),
            DimensionCounts {
                assessed: result.trace_assessed_tests,
                passed: result.trace_assessed_tests.saturating_sub(trace_failed),
            },
        );

        // The suite digest names where the cases were read from when a
        // filed baseline document existed — one fold implementation,
        // shared with the harness-error pair (P25.6).
        let baseline_suite_digest = self.suite_digest(baseline_tests, context)?;

        let mut receipt = VerificationReceipt {
            binary: BinaryIdentity::new(binary),
            function: function.to_string(),
            attempt: context.attempt,
            retry_strategy: context.retry_strategy.to_string(),
            attempt_path: context.attempt_path.to_string(),
            verifier_command,
            baseline_suite_digest,
            dimensions,
            compile_ms,
            test_run_ms,
            total_ms: compile_ms + test_run_ms,
            verdict,
            failed_cases: result.failed_tests.iter().map(|f| f.test_index).collect(),
            digest: String::new(),
        };
        receipt.digest = receipt
            .content_digest()
            .map_err(|e| anyhow::anyhow!("failed to fold the receipt digest: {e}"))?;

        if let Err(filing) = self.write_receipt_pair(&receipt) {
            // P25.6 (issue #415): the pair cannot land. The missing
            // authority is filed as an admitted unknown naming the run it
            // belongs to — never dropped as a log line. The run's own
            // verdict was already earned by the gate; it stands, honestly
            // degraded, and the record tree says out loud that this run's
            // pair is missing. If even the unknown cannot be filed, the
            // failure surfaces loudly as an error.
            let record_id = self
                .file_unfiled_receipt_unknown(
                    binary,
                    function,
                    receipt.attempt,
                    &format!("the receipt pair could not be filed: {filing}"),
                )
                .map_err(|unknown| {
                    anyhow::anyhow!(
                        "failed to file the receipt pair: {filing}; the run's pair is \
                         unfiled and even the admitted unknown could not be filed: {unknown:#}"
                    )
                })?;
            warn!(
                binary,
                function,
                attempt = receipt.attempt,
                record_id = %record_id,
                "verification receipt pair unfiled; admitted unknown filed in its place"
            );
            return Ok(receipt);
        }

        info!(
            binary,
            function,
            attempt = receipt.attempt,
            digest = %receipt.digest,
            "Verification receipt filed"
        );
        Ok(receipt)
    }

    /// Fold the run's baseline suite digest: where the cases were read
    /// from, when a filed baseline document existed, relative to the
    /// record-tree root this verifier files under so the location stays
    /// portable. The fold is deterministic — two runs over the same suite
    /// and location fold the same digest whatever the verdict turns out
    /// to be.
    fn suite_digest(
        &self,
        baseline_tests: &[TestCase],
        context: &VerifyContext<'_>,
    ) -> Result<String> {
        let baseline_location = context.baseline_file.map(|path| {
            let relative = path.strip_prefix(&self.work_dir).unwrap_or(path);
            relative.display().to_string()
        });
        calxgloss_types::baseline_suite_digest(baseline_tests, baseline_location.as_deref())
            .map_err(|e| anyhow::anyhow!("failed to fold the baseline suite digest: {e}"))
    }

    /// Write one receipt as its digest-paired md+json pair under the
    /// record convention. The JSON authority is filed first: a twin beside
    /// a missing authority is never attempted, so the key either holds a
    /// complete pair or says nothing about the run. Returns the JSON
    /// member's path for the caller's logs.
    fn write_receipt_pair(&self, receipt: &VerificationReceipt) -> Result<PathBuf> {
        let json_path = verification_receipt_path(
            &self.work_dir,
            &receipt.binary,
            &receipt.function,
            receipt.attempt,
        );
        persist::save_json(&json_path, receipt)
            .map_err(|e| anyhow::anyhow!("failed to file the receipt {json_path:?}: {e}"))?;
        let md_path = json_path.with_extension("md");
        if let Err(twin) = std::fs::write(&md_path, verification_receipt_markdown(receipt)) {
            // Pair-or-nothing: a lone JSON authority without its twin is a
            // half-pair no reader can pairing-check. Retract the authority
            // this run just wrote so the key says nothing about the run
            // rather than half a story.
            return Err(match std::fs::remove_file(&json_path) {
                Ok(()) => anyhow::anyhow!(
                    "failed to file the receipt twin {md_path:?}: {twin} \
                     (the half-filed authority was retracted)"
                ),
                Err(cleanup) => anyhow::anyhow!(
                    "failed to file the receipt twin {md_path:?}: {twin}; and the half-filed \
                     authority could not even be retracted: {cleanup}"
                ),
            });
        }
        Ok(json_path)
    }

    /// P25.6 (issue #415): the verifier toolchain broke before the unit
    /// could be judged — the run still files its pair, verdicted
    /// `harness-error`: no baseline case was assessed, no case is named,
    /// and the compile-only command doctrine says so plainly (the same
    /// one a compile-failed pair keeps). The seam hands back `Err`, never
    /// a [`VerificationResult`]: the unit was never judged, so there is
    /// no verdict to give. A harness-error pair that itself cannot be
    /// written files an admitted unknown naming the run it belongs to;
    /// the harness failure is still handed back, unsoftened.
    // The run's facts are passed positionally — identity, place-in-sequence,
    // the folded suite digest, the break reason, and the two leg timings —
    // the same shape as `file_receipt`'s positional facts above.
    #[allow(clippy::too_many_arguments)]
    fn file_harness_error_receipt(
        &self,
        binary: &str,
        function: &str,
        context: &VerifyContext<'_>,
        suite_digest: &str,
        reason: &str,
        compile_ms: u64,
        test_run_ms: u64,
    ) -> Result<()> {
        error!(
            binary,
            function,
            attempt = context.attempt,
            reason,
            "verifier harness failure; filing the harness-error receipt pair"
        );
        let mut receipt = VerificationReceipt {
            binary: BinaryIdentity::new(binary),
            function: function.to_string(),
            attempt: context.attempt,
            retry_strategy: context.retry_strategy.to_string(),
            attempt_path: context.attempt_path.to_string(),
            // No baseline case ever ran through a runner — the honest
            // command is compile-only, whatever the run meant to do.
            verifier_command: VerifierCommand::CompileOnly,
            baseline_suite_digest: suite_digest.to_string(),
            dimensions: BTreeMap::new(),
            compile_ms,
            test_run_ms,
            total_ms: compile_ms + test_run_ms,
            verdict: VerificationVerdict::HarnessError,
            // No unit verdict means no case to name.
            failed_cases: Vec::new(),
            digest: String::new(),
        };
        // Nothing was assessed, so nothing passed — on either dimension.
        for dimension in ["values", "api_trace"] {
            receipt.dimensions.insert(
                dimension.to_string(),
                DimensionCounts {
                    assessed: 0,
                    passed: 0,
                },
            );
        }
        receipt.digest = receipt
            .content_digest()
            .map_err(|e| anyhow::anyhow!("failed to fold the harness-error digest: {e}"))?;

        match self.write_receipt_pair(&receipt) {
            Ok(path) => {
                info!(
                    binary,
                    function,
                    attempt = receipt.attempt,
                    path = %path.display(),
                    digest = %receipt.digest,
                    "harness-error receipt pair filed"
                );
                Ok(())
            }
            Err(filing) => {
                // Even the honesty artifact could not land: file the
                // unknown that says so, and let the caller keep holding
                // the harness failure itself.
                let record_id = self.file_unfiled_receipt_unknown(
                    binary,
                    function,
                    context.attempt,
                    &format!("the harness-error receipt pair could not be filed: {filing}"),
                )?;
                error!(
                    binary,
                    function,
                    record_id = %record_id,
                    "harness-error pair unfiled; the missing receipt is an admitted unknown"
                );
                Ok(())
            }
        }
    }

    /// File the admitted unknown saying one verify run's receipt pair
    /// never landed, naming the run by its attempt slot and the pair path
    /// it belongs to. Merged into the binary's own ledger document: every
    /// landed record keeps its place under the revision doctrine
    /// (issue #368), and re-filing the same run stays one record — the id
    /// re-derives from binary, function, kind, and slot. An unreadable
    /// ledger or resolutions document is a hard refusal, never a silent
    /// overwrite. Returns the record's id.
    pub fn file_unfiled_receipt_unknown(
        &self,
        binary: &str,
        function: &str,
        attempt: u32,
        reason: &str,
    ) -> Result<String> {
        let identity = BinaryIdentity::new(binary);
        let pair_path = verification_receipt_path(&self.work_dir, &identity, function, attempt);
        let record = UnknownRecord::derive(
            identity.clone(),
            Some(function.to_string()),
            UnknownKind::ReceiptUnfiled,
            UnknownSeverity::Blocking,
            format!(
                "verification of {binary}/{function} (attempt {attempt}) finished without its \
                 receipt pair at {} ever landing: {reason} — which verify run carries this \
                 unit's digest claim?",
                pair_path.display()
            ),
            format!(
                "the digest-paired md+json pair at {} stands on disk, or the run is re-run \
                 and files it",
                pair_path.display()
            ),
            UnknownOrigin::VerifyRun { attempt },
            now_unix_secs(),
        );
        let path = unknown_ledger_path(&self.work_dir, &identity);
        let reopened = match persist::load_json::<UnknownResolutions>(&unknown_resolutions_path(
            &self.work_dir,
        )) {
            Ok(resolutions) => resolutions.reopened,
            Err(PersistError::NotFound { .. }) => BTreeMap::new(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "refusing to file an unfiled-receipt unknown over an unreadable \
                     resolutions document at {}: {e}",
                    unknown_resolutions_path(&self.work_dir).display()
                ));
            }
        };
        let landed = match persist::load_json::<UnknownLedger>(&path) {
            Ok(ledger) => Some(ledger),
            Err(PersistError::NotFound { .. }) => None,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "refusing to file an unfiled-receipt unknown over an unreadable \
                     ledger at {}: {e}",
                    path.display()
                ));
            }
        };
        // The derived set for this filing: this run's record plus every
        // landed record under another id, so a pipeline batch's records
        // keep their place in their own document.
        let mut derived: Vec<UnknownRecord> = landed
            .as_ref()
            .and_then(|ledger| ledger.records.as_ref())
            .map(|records| {
                records
                    .iter()
                    .filter(|landed| landed.id != record.id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        derived.push(record.clone());
        let filed = UnknownLedger::file(
            identity,
            landed.as_ref(),
            &derived,
            &reopened,
            now_unix_secs(),
        );
        persist::save_json(&path, &filed).with_context(|| {
            format!("filing the unfiled-receipt unknown into {}", path.display())
        })?;
        info!(
            binary,
            function,
            attempt,
            record_id = %record.id,
            "the unfiled verification receipt is now an admitted unknown"
        );
        Ok(record.id)
    }

    // ---- Internal helpers ----

    /// Ensure the shared PAL crate exists at `{work_dir}/scratch/pal/`.
    ///
    /// The PAL crate is created once per workspace.  All scratch projects
    /// depend on it, so this only needs to run once before any scaffold.
    fn ensure_pal_crate(&self) {
        let pal_dir = self.work_dir.join("scratch").join("pal");
        // Compare content, not mere existence: an older scaffold may have
        // written a stale (or uncompilable) template, and the scratch tree
        // should self-heal to the embedded one.
        let content_path = pal_dir.join("src").join("stub_content.rs");
        if std::fs::read_to_string(&content_path).ok().as_deref() == Some(PAL_STUB_CONTENT) {
            return;
        }

        debug!(path = %pal_dir.display(), "Creating shared PAL crate");
        let _ = std::fs::create_dir_all(pal_dir.join("src"));

        // Cargo.toml for the shared PAL crate
        let cargo_toml = r#"[package]
name = "calxgloss-verify-pal"
version = "0.1.0"
edition = "2021"

[dependencies]
"#;
        std::fs::write(pal_dir.join("Cargo.toml"), cargo_toml).ok();

        // lib.rs that includes the embedded stub content
        let lib_rs = r#"// Stub content from stubs.rs.
include!("stub_content.rs");
"#;
        std::fs::write(pal_dir.join("src").join("lib.rs"), lib_rs).ok();

        // Copy stub content (embedded at compile time via include_str!)
        let _ = std::fs::write(&content_path, PAL_STUB_CONTENT);
    }

    /// Scaffold a minimal Cargo project for compilation verification.
    fn scaffold_project(&self, binary: &str, function: &str, rust_code: &str) -> Result<PathBuf> {
        self.ensure_pal_crate();
        let project_dir = self.create_scratch_dir(binary, function);

        let cargo_toml = format!(
            "[package]\nname = \"{}_verify\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npal = {{ path = \"../pal\", package = \"calxgloss-verify-pal\" }}\nserde_json = \"1\"\n\n[lib]\nname = \"{}_lib\"\npath = \"src/lib.rs\"\n",
            sanitize_crate_name(binary),
            sanitize_identifier(function),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create src directory")?;

        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str("use pal::*;\n\n");
        lib_rs.push_str("// ===== Translated function =====\n\n");
        lib_rs.push_str(rust_code);

        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write lib.rs")?;

        debug!(project = %project_dir.display(), "Scaffolded scratch project");
        Ok(project_dir)
    }

    /// Scaffold a Cargo project with behavioral test runner.
    fn scaffold_test_project(
        &self,
        binary: &str,
        function: &str,
        rust_code: &str,
        baseline_tests: &[TestCase],
    ) -> Result<PathBuf> {
        self.ensure_pal_crate();
        let project_dir = self.create_scratch_dir(binary, function);

        let cargo_toml = format!(
            "[package]\nname = \"{}_verify\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npal = {{ path = \"../pal\", package = \"calxgloss-verify-pal\" }}\nserde = {{ version = \"1\", features = [\"derive\"] }}\nserde_json = \"1\"\n\n[lib]\nname = \"{}_lib\"\npath = \"src/lib.rs\"\n\n[[bin]]\nname = \"{}_runner\"\npath = \"src/main.rs\"\n",
            sanitize_crate_name(binary),
            sanitize_identifier(function),
            sanitize_identifier(function),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create src directory")?;

        // Write stubs (from pal crate) + translated code for lib.rs
        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str("use pal::*;\n\n");
        lib_rs.push_str("// ===== Translated function =====\n\n");
        lib_rs.push_str(rust_code);
        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write lib.rs")?;

        // Write test runner binary
        let test_harness = self.generate_test_harness(function, baseline_tests, rust_code);
        std::fs::write(project_dir.join("src").join("main.rs"), test_harness)
            .context("Failed to write test runner")?;

        // Save baseline JSON for the runner
        let baseline_json = serde_json::to_string_pretty(baseline_tests)
            .context("Failed to serialize baseline tests")?;
        std::fs::write(project_dir.join("baseline.json"), baseline_json)
            .context("Failed to write baseline.json")?;

        debug!(project = %project_dir.display(), test_count = baseline_tests.len(), "Scaffolded test project");
        Ok(project_dir)
    }

    /// Create a scratch subdirectory in the working directory.
    fn create_scratch_dir(&self, binary: &str, function: &str) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);

        let dir_name = format!(
            "{}_{}_{}",
            sanitize_identifier(binary),
            sanitize_identifier(function),
            timestamp
        );

        let project_dir = self.work_dir.join("scratch").join(dir_name);
        let _ = std::fs::create_dir_all(&project_dir);
        project_dir
    }

    /// Generate a test runner that **calls the translated unit** with each
    /// baseline case's positional inputs, and judges what came back.
    fn generate_test_harness(
        &self,
        function: &str,
        baseline_tests: &[TestCase],
        rust_code: &str,
    ) -> String {
        let mut code = String::new();

        // Import the translated library and shared PAL types
        let lib_name = sanitize_crate_name(function);
        code.push_str(&format!("use {}_lib::*;\n", lib_name));
        code.push_str("use pal::*;\n");
        code.push_str("use serde_json::Value;\n\n");

        code.push_str(
            r#"// Test runner for behavioral verification
//
// The runner CALLS the translated unit. A baseline case's inputs are a
// positional value: null means no arguments, and a JSON array calls the
// unit with one coerced argument per element, in order. Inputs the
// coercion cannot speak make THAT CASE fail — naming the input and its
// position — and a unit that panics fails its case rather than taking
// the harness down with it.
//
// Two dimensions judge each case. The VALUES dimension is assessed only
// when the baseline carries an expected return and the runner actually
// called the unit with it: an expected null leaves the value verdict
// unassessed, and the runner says out loud when it never compared a
// value (ADR-0057 — silence never counts as a pass). The TRACE dimension
// is assessed when the case carries a recorded API-call trace: the
// expected names must appear in order, repetitions intact, inside the
// ordered verify-PAL-surface call sequence as a subsequence (ordered
// containment). Extra surface entries never fail: they are entries the
// capture vocabulary cannot speak. An empty expected trace leaves the
// trace dimension unassessed the same way.

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct TestCaseInput {
    inputs: Value,
    expected_return: Value,
    #[serde(default)]
    expected_api_calls: Vec<String>,
}

#[derive(Serialize)]
struct TestResult {
    test_index: usize,
    expected: Value,
    actual: Value,
    passed: bool,
    error: Option<String>,
    expected_api_calls: Vec<String>,
    actual_api_calls: Vec<String>,
    trace_divergence_index: Option<usize>,
    trace_assessed: bool,
    value_assessed: bool,
}

fn main() {
    let baseline_raw = std::fs::read_to_string("baseline.json")
        .expect("baseline.json not found");
    let tests: Vec<TestCaseInput> = serde_json::from_str(&baseline_raw)
        .expect("Failed to parse baseline.json");

    let results: Vec<TestResult> = tests.iter().enumerate().map(|(i, t)| {
        pal::begin_api_trace();
        // A unit that panics is a failing case, not a dead harness: the
        // panic is caught, named in the case's error, and every other
        // case still gets its row.
        let call = std::panic::catch_unwind(|| call_function(&t.inputs));
        let actual_api_calls = pal::take_api_trace();
        let (output, call_error) = match call {
            Ok(Ok(value)) => (value, None),
            Ok(Err(reason)) => (Value::Null, Some(reason)),
            Err(panic) => {
                let reason = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "panicked without a message".to_string());
                (Value::Null, Some(format!("the unit panicked: {reason}")))
            }
        };
        judge(i, t, output, call_error, actual_api_calls)
    }).collect();

    println!("{}", serde_json::to_string(&results).unwrap());
}

fn judge(
    i: usize,
    t: &TestCaseInput,
    output: Value,
    call_error: Option<String>,
    actual_api_calls: Vec<String>,
) -> TestResult {
    let trace_assessed = !t.expected_api_calls.is_empty();
    let trace_divergence_index = if trace_assessed {
        // Greedy containment walk: each expected name must be found in the
        // actual route at or after the position where the previous one
        // matched. The divergence index names where the search gave up its
        // hunt for the first unhonoured expected call: 0 when the very first
        // was never found, the position just after the last honoured call
        // for a later one, and the route's own length when the search ran
        // off its end.
        let mut cursor = 0usize;
        let mut divergence = None;
        for expected in &t.expected_api_calls {
            match actual_api_calls[cursor..].iter().position(|actual| actual == expected) {
                Some(hit) => cursor += hit + 1,
                None => {
                    divergence = Some(cursor);
                    break;
                }
            }
        }
        divergence
    } else {
        None
    };
    // The values dimension is assessed exactly when the case carried an
    // expected return AND the runner called the unit to compare against
    // it. An uncallable input or a null expectation leaves it unassessed —
    // never a vacuous pass, never a fabricated failure.
    let value_assessed = call_error.is_none() && t.expected_return != Value::Null;
    let value_error = if !value_assessed {
        None
    } else if output == t.expected_return {
        None
    } else {
        Some(format!("expected {}, got {}", t.expected_return, output))
    };
    let trace_error = trace_divergence_index.map(|pos| format!(
        "API-call trace divergence at position {}: expected [{}], got [{}]",
        pos,
        t.expected_api_calls.join(", "),
        actual_api_calls.join(", "),
    ));
    let error = [call_error, value_error, trace_error]
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" — ");
    let error = (!error.is_empty()).then_some(error);
    TestResult {
        test_index: i,
        expected: t.expected_return.clone(),
        actual: output,
        passed: error.is_none(),
        error,
        expected_api_calls: t.expected_api_calls.clone(),
        actual_api_calls,
        trace_divergence_index,
        trace_assessed,
        value_assessed,
    }
}

fn to_json<T: serde::Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value)
        .map_err(|e| format!("the unit returned a value JSON cannot carry: {e}"))
}

/// Coercion from one JSON input to the unit's parameter type at a
/// position. The unit's own signature picks which impl applies; inputs
/// outside it fail the case by name and position.
trait JsonArg: Sized {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String>;
}

fn json_arg<T: JsonArg>(value: &Value, position: usize) -> Result<T, String> {
    T::json_arg(value, position)
}

macro_rules! numeric_arg {
    ($($t:ty),*) => {
        $(
            impl JsonArg for $t {
                fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
                    if let Some(n) = value.as_i64() {
                        return <$t>::try_from(n)
                            .map_err(|_| format!("input {position} ({n}) is outside {}'s range", stringify!($t)));
                    }
                    if let Some(n) = value.as_u64() {
                        return <$t>::try_from(n)
                            .map_err(|_| format!("input {position} ({n}) is outside {}'s range", stringify!($t)));
                    }
                    // A float spelling of an integer argument must be whole
                    // and inside the declared range — never a silent truncation.
                    if let Some(f) = value.as_f64() {
                        let fits = f.fract() == 0.0
                            && f >= <$t>::MIN as f64
                            && f <= <$t>::MAX as f64;
                        return if fits {
                            Ok(f as $t)
                        } else {
                            Err(format!(
                                "input {position} ({f}) is not a whole {}",
                                stringify!($t)
                            ))
                        };
                    }
                    Err(format!("input {position} is not a number: {value}"))
                }
            }
        )*
    };
}

numeric_arg!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl JsonArg for f32 {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        value
            .as_f64()
            .and_then(|f| {
                let narrowed = f as f32;
                (f64::from(narrowed) == f).then_some(narrowed)
            })
            .ok_or_else(|| format!("input {position} is not an f32-representable number: {value}"))
    }
}

impl JsonArg for f64 {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        value
            .as_f64()
            .ok_or_else(|| format!("input {position} is not a number: {value}"))
    }
}

impl JsonArg for bool {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        value
            .as_bool()
            .ok_or_else(|| format!("input {position} is not a boolean: {value}"))
    }
}

impl JsonArg for String {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("input {position} is not a string: {value}"))
    }
}

impl JsonArg for char {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        value
            .as_u64()
            .and_then(|code| u32::try_from(code).ok())
            .and_then(char::from_u32)
            .ok_or_else(|| format!("input {position} is not a char code: {value}"))
    }
}

impl<T> JsonArg for *mut T {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        pointer_address(value, position).map(|addr| addr as *mut T)
    }
}

impl<T> JsonArg for *const T {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        pointer_address(value, position).map(|addr| addr as *const T)
    }
}

fn pointer_address(value: &Value, position: usize) -> Result<usize, String> {
    match value {
        Value::Null => Ok(0),
        _ => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|i| u64::try_from(i).ok()))
            .map(|addr| addr as usize)
            .ok_or_else(|| format!("input {position} is not a pointer address: {value}")),
    }
}

impl<T: JsonArg> JsonArg for Option<T> {
    fn json_arg(value: &Value, position: usize) -> Result<Self, String> {
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(T::json_arg(value, position)?))
    }
}

fn call_function(inputs: &Value) -> Result<Value, String> {
"#,
        );

        // Generate the dispatch arms (these close the match with their own
        // unmatched-input fallback, so only the fn closes here). When the
        // unit is declared unsafe, its calls need an explicit unsafe block.
        let unsafe_unit = self.unit_is_unsafe(function, rust_code);
        code.push_str(&self.generate_input_patterns(function, baseline_tests, unsafe_unit));

        code.push_str("}\n");

        code
    }

    /// Generate the unit's dispatch arms, one per distinct input shape the
    /// suite feeds: null calls with no arguments, an array of length `n`
    /// calls with `n` coerced arguments, and a bare number, bool, or string
    /// calls with that single argument. Anything else fails the case with
    /// a message naming the unit and the input.
    fn generate_input_patterns(
        &self,
        function: &str,
        baseline_tests: &[TestCase],
        unsafe_unit: bool,
    ) -> String {
        let unit = sanitize_identifier(function);
        // Rust 2024: calling an unsafe fn requires an unsafe block at the
        // call site; a plain block around a safe call would warn.
        let call = |args: String| {
            if unsafe_unit {
                format!("unsafe {{ {unit}({args}) }}")
            } else {
                format!("{unit}({args})")
            }
        };

        // The suite repeats shapes heavily — collect each shape once.
        let mut shapes = std::collections::BTreeSet::new();
        for test in baseline_tests {
            let shape = match &test.inputs {
                serde_json::Value::Null => InputShape::NoArgs,
                serde_json::Value::Bool(_) => InputShape::OneBool,
                serde_json::Value::Number(_) => InputShape::OneNumber,
                serde_json::Value::String(_) => InputShape::OneString,
                serde_json::Value::Array(arr) => InputShape::Args(arr.len()),
                // A named object is not a callable shape; the unmatched
                // fallback below fails those cases honestly.
                serde_json::Value::Object(_) => continue,
            };
            shapes.insert(shape);
        }

        let mut code = String::new();
        code.push_str("    match inputs {\n");
        for shape in shapes {
            match shape {
                InputShape::NoArgs => code.push_str(&format!(
                    "        Value::Null => to_json({}),\n",
                    call(String::new())
                )),
                InputShape::OneBool => code.push_str(&format!(
                    "        Value::Bool(_) => to_json({}),\n",
                    call("json_arg(inputs, 0)?".to_string())
                )),
                InputShape::OneNumber => code.push_str(&format!(
                    "        Value::Number(_) => to_json({}),\n",
                    call("json_arg(inputs, 0)?".to_string())
                )),
                InputShape::OneString => code.push_str(&format!(
                    "        Value::String(_) => to_json({}),\n",
                    call("json_arg(inputs, 0)?".to_string())
                )),
                InputShape::Args(len) => {
                    let args = (0..len)
                        .map(|i| format!("json_arg(&arr[{i}], {i})?"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    code.push_str(&format!(
                        "        Value::Array(arr) if arr.len() == {len} => to_json({}),\n",
                        call(args)
                    ));
                }
            }
        }

        // Anything the suite feeds that the runner cannot speak — a named
        // object, or an arity the unit's own definition never had — fails
        // the case honestly. It never calls a stand-in function, and it
        // never returns a sentinel that could vacuously match an
        // expectation.
        code.push_str(&format!(
            "        other => Err(format!(\"{{other}} gives {unit} no callable arguments\")),\n"
        ));
        code.push_str("    }\n");

        code
    }

    /// True when the named unit is declared `unsafe fn`: the 2024 edition
    /// demands an explicit unsafe block at its call sites, so the generated
    /// dispatch arms wrap the call only when the unit's own definition is
    /// unsafe. A safe unit keeps plain calls; wrapping those would warn.
    fn unit_is_unsafe(&self, function: &str, rust_code: &str) -> bool {
        let name = sanitize_identifier(function);
        for line in rust_code.lines() {
            let line = line.trim();
            // `pub unsafe fn <name>` or `unsafe fn <name>`, with a possible
            // generic suffix on the name — but not a call of it.
            let Some(rest) = line
                .strip_prefix("pub unsafe fn ")
                .or_else(|| line.strip_prefix("unsafe fn "))
            else {
                continue;
            };
            let Some(after_name) = rest.strip_prefix(&name) else {
                continue;
            };
            // The name must end at a boundary: `(` opens the parameters,
            // `<` the generics, whitespace or end separates a longer name
            // (`TickTick`) from the unit we are naming (`Tick`).
            if after_name
                .chars()
                .next()
                .is_some_and(|next| next == '(' || next == '<' || next.is_whitespace())
            {
                return true;
            }
        }
        false
    }

    // ---- Shim layer verification ----

    /// Verify a shim layer by compiling its generated code and running its tests.
    ///
    /// This is the shim-layer equivalent of [`Self::verify`].  It takes raw
    /// shim source and test code (as produced by `calxgloss-analysis::shim_gen`
    /// and `calxgloss-analysis::shim_test_gen`), scaffolds a sandboxed Cargo
    /// project, compiles it, runs `cargo test`, and returns a
    /// [`ShimVerificationResult`] describing the outcome.
    ///
    /// # Arguments
    ///
    /// * `shim_source` — The generated shim module source code.
    /// * `shim_tests` — The generated test module source code.
    /// * `target_crate` — The Rust crate name for the dependency
    ///   (e.g. `"wgpu"`, `"cpal"`).  The dependency is added under the same
    ///   name in the scaffolded `Cargo.toml`.
    /// * `dll_name` — The original DLL name, used for project identification
    ///   and to derive the module name.
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// use calxgloss_verify::Verifier;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let shim_source = r#"pub unsafe fn set_texture(stage: u32, texture: *mut c_void) { }"#;
    /// let shim_tests = r#"#[cfg(test)] mod shim_tests { #[test] fn test_placeholder() {} }"#;
    ///
    /// let verifier = Verifier::new(std::path::Path::new("/tmp/calxgloss-work"))?;
    /// let result = verifier.verify_shim(shim_source, shim_tests, "wgpu", "d3d9.dll").await?;
    ///
    /// assert!(result.compiled);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, shim_source, shim_tests), fields(binary, target_crate))]
    pub async fn verify_shim(
        &self,
        shim_source: &str,
        shim_tests: &str,
        target_crate: &str,
        dll_name: &str,
    ) -> Result<ShimVerificationResult> {
        debug!(binary = dll_name, "Starting shim verification");

        // Scaffold a shim project and compile it.
        let project =
            self.scaffold_shim_project(dll_name, shim_source, shim_tests, target_crate)?;
        let compile_output = cargo::run_cargo_check(&project)
            .await
            .context("cargo check failed for shim")?;
        let (compiled, compilation_errors, compilation_warnings) =
            parse::parse_cargo_output(&compile_output);

        if !compiled {
            info!(
                binary = dll_name,
                error_count = compilation_errors.len(),
                "Shim verification failed at compilation"
            );
            return Ok(ShimVerificationResult {
                compiled: false,
                compilation_errors,
                compilation_warnings,
                tests_passed: 0,
                tests_total: 0,
                edge_tests_passed: 0,
                edge_tests_total: 0,
                failed_tests: Vec::new(),
                mapping_results: Vec::new(),
            });
        }

        info!(
            binary = dll_name,
            "Shim compiled successfully, running tests"
        );

        // Run the shim's tests.
        let test_output = Self::run_cargo_test(&project)
            .await
            .unwrap_or_else(|e| format!("Test execution failed: {}", e));

        // Parse test results from the test output.
        let (
            tests_passed,
            tests_total,
            edge_tests_passed,
            edge_tests_total,
            failed_tests,
            mapping_results,
        ) = parse::parse_shim_test_results(&test_output, shim_source, shim_tests);

        info!(
            binary = dll_name,
            tests_passed, tests_total, "Shim verification complete"
        );

        Ok(ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings,
            tests_passed,
            tests_total,
            edge_tests_passed,
            edge_tests_total,
            failed_tests,
            mapping_results,
        })
    }

    /// Scaffold a Cargo project containing shim source and shim tests.
    ///
    /// Creates a minimal project with the shim as a library module, the
    /// target crate as a dependency, and the test module included via an
    /// `include!` so the tests run alongside the code.
    fn scaffold_shim_project(
        &self,
        dll_name: &str,
        shim_source: &str,
        shim_tests: &str,
        target_crate: &str,
    ) -> Result<PathBuf> {
        let project_dir = self.create_scratch_dir(dll_name, "shim");

        // Determine the crate root mapping for Cargo.toml.
        let dep_crate = Self::shim_crate_root_for_cargo(target_crate);

        let cargo_toml = format!(
            "[package]\nname = \"{}_shim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{dep_crate} = {{ version = \"*\", optional = true }}\n\n[features]\ndefault = []\n\n[lib]\nname = \"{}_shim_lib\"\npath = \"src/lib.rs\"\n",
            sanitize_crate_name(dll_name),
            sanitize_identifier(dll_name),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write shim Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create shim src directory")?;

        // Build the lib.rs: shim source + include the test module so cargo test picks it up.
        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str(shim_source);
        lib_rs.push('\n');

        // Write the tests to a separate file and include them.
        let tests_path = "shim_tests.rs";
        let tests_dir = project_dir.join("src");
        std::fs::write(tests_dir.join(tests_path), shim_tests)
            .context("Failed to write shim test file")?;

        // Add include! at the end of lib.rs to bring tests into scope.
        // If the test module already has #[cfg(test)], the include! brings it in.
        lib_rs.push_str(&format!(
            "#[path = \"{tests_path}\"]\nmod shim_tests;\n",
            tests_path = tests_path,
        ));

        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write shim lib.rs")?;

        debug!(
            project = %project_dir.display(),
            "Scaffolded shim scratch project"
        );
        Ok(project_dir)
    }

    /// Resolve a crate name to its Cargo dependency name.
    fn shim_crate_root_for_cargo(crate_name: &str) -> String {
        match crate_name {
            "wgpu" => "wgpu = \"*\"".to_string(),
            "tiny-skia" => "tiny_skia = \"*\"".to_string(),
            "cpal" => "cpal = \"*\"".to_string(),
            "fmod-rs" => "fmod_rs = \"*\"".to_string(),
            "vb6runtime" => "vb6runtime = \"*\"".to_string(),
            _ => format!("{crate_crate} = \"*\"", crate_crate = crate_name),
        }
    }

    /// Run `cargo test` in the given project directory.
    async fn run_cargo_test(project: &Path) -> Result<String> {
        debug!(project = %project.display(), "Running cargo test");

        let output = tokio::process::Command::new("cargo")
            .arg("test")
            .current_dir(project)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to spawn cargo test")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stderr, stdout);

        if output.status.success() {
            debug!("cargo test succeeded");
        } else {
            debug!(
                output = &combined[..combined.len().min(500)],
                "cargo test failed"
            );
        }

        Ok(combined.to_owned())
    }
}

/// The verifier's own break, chained with the failure of its honesty
/// filing: the harness error is the finding, and the failed filing rides
/// beside it — both losses stay loud, never one swallowed by the other.
fn harness_fault(harness: anyhow::Error, honesty: anyhow::Error) -> anyhow::Error {
    harness.context(format!(
        "and its harness-error honesty filing failed too: {honesty:#}"
    ))
}

/// A gate whose test leg never ran: nothing passed, nothing failed, and
/// no dimension assessed anything. The counters count tests that RAN, so
/// an unrun suite counts as zero, not as suite size — downstream "did any
/// baseline case run" questions read this directly.
fn unrun_suite_result(compilation_errors: Vec<String>) -> VerificationResult {
    VerificationResult {
        compiled: false,
        compilation_errors,
        tests_passed: 0,
        tests_total: 0,
        failed_tests: Vec::new(),
        trace_assessed_tests: 0,
        value_assessed_tests: 0,
        values_matched_tests: 0,
    }
}

/// One distinct input spelling the suite feeds the generated runner,
/// collected so each dispatch arm is generated once. Declaration order
/// is generation order: null, then bare scalars, then arrays by length.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum InputShape {
    NoArgs,
    OneBool,
    OneNumber,
    OneString,
    /// A JSON array to destructure into `n` positional arguments.
    Args(usize),
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Stubs;
    use crate::{parse_cargo_output, parse_test_line, parse_test_results};
    use std::fs;

    #[test]
    fn test_verifier_creation() {
        let dir = std::env::temp_dir().join("calxgloss_verify_test_creation");
        let _ = fs::remove_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();
        assert!(dir.exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = verifier;
    }

    #[test]
    fn pal_stub_content_carries_no_inner_doc_comments() {
        // The scratch PAL crate splices this file in with `include!`, and
        // inner doc comments inside a macro expansion fail to compile with
        // E0753 — the shared crate would never build, and every verification
        // would fail on scaffold code the LLM never wrote.
        for line in PAL_STUB_CONTENT.lines() {
            assert!(
                !line.trim_start().starts_with("//!"),
                "stub content carries an inner doc comment: {line}"
            );
        }
    }

    #[test]
    fn ensure_pal_crate_rewrites_a_stale_stub_content() {
        // An older scaffold's stub_content.rs must self-heal to the embedded
        // template, not be kept just because it exists.
        let dir = std::env::temp_dir().join("calxgloss_verify_test_pal_heal");
        let _ = fs::remove_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();
        verifier.ensure_pal_crate();
        let content = dir
            .join("scratch")
            .join("pal")
            .join("src")
            .join("stub_content.rs");
        fs::write(&content, "//! stale template").unwrap();
        verifier.ensure_pal_crate();
        assert_eq!(fs::read_to_string(&content).unwrap(), PAL_STUB_CONTENT);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_crate_name() {
        assert_eq!(sanitize_crate_name("game_logic.dll"), "game_logic_dll");
        assert_eq!(sanitize_crate_name("my-app"), "my-app");
        assert_eq!(sanitize_crate_name("test_app"), "test_app");
    }

    #[test]
    fn test_sanitize_identifier() {
        assert_eq!(sanitize_identifier("DrawSprite"), "DrawSprite");
        assert_eq!(sanitize_identifier("123test"), "_123test");
        assert_eq!(sanitize_identifier("my_func"), "my_func");
        assert_eq!(sanitize_identifier("hello-world"), "hello_world");
    }

    #[test]
    fn test_parse_cargo_output_empty() {
        let (success, errors, warnings) = parse_cargo_output("");
        assert!(success);
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_with_error() {
        let output = r#"error[E0308]: mismatched types
  --> src/lib.rs:5:12
   |
5  |     return "hello";
   |             ^^^^^^^ expected `i32`, found `&str`

error: could not compile (exit status: 1)
"#;
        let (success, errors, _warnings) = parse_cargo_output(output);
        assert!(!success);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_with_warnings() {
        let output = r#"warning: unused variable: `x`
  --> src/lib.rs:3:9
   |
3  |     let x = 42;
   |         ^ help: if this is intentional, prefix it with an underscore: `_x`

warning: 1 warning emitted
"#;
        let (success, errors, warnings) = parse_cargo_output(output);
        assert!(success);
        assert!(errors.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_mixed() {
        let output = r#"warning: unused variable
  --> src/lib.rs:1:5
error[E0308]: mismatched types
  --> src/lib.rs:5:12
"#;
        let (success, errors, warnings) = parse_cargo_output(output);
        assert!(!success);
        assert!(!errors.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_test_results_empty() {
        let baseline = vec![TestCase {
            inputs: serde_json::json!({}),
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];
        let report = parse_test_results("", &baseline);
        assert_eq!(report.passed, 0);
        assert_eq!(report.total, 1);
        assert!(report.failed.is_empty());
        assert_eq!(report.trace_assessed, 0);
        assert!(
            !report.produced_results,
            "a runner that printed no rows produced no verdicts to fold"
        );
    }

    /// Issue #416's row shape: the runner itself names what each dimension
    /// assessed, so uncallable inputs and expected-null cases stay honest.
    #[test]
    fn the_new_runner_rows_name_the_values_dimension_directly() {
        let json = r#"[{"test_index":0,"expected":null,"actual":42,"passed":true,"error":null,"trace_assessed":false,"value_assessed":false},{"test_index":1,"expected":null,"actual":null,"passed":false,"error":"{\"param_0\":1} gives MyFunc no callable arguments","trace_assessed":false,"value_assessed":false},{"test_index":2,"expected":7,"actual":7,"passed":true,"error":null,"trace_assessed":false,"value_assessed":true}]"#;
        let make_case = |inputs: serde_json::Value, expected: serde_json::Value| TestCase {
            inputs,
            expected_return: expected,
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        };
        let baseline = vec![
            make_case(serde_json::json!([42]), serde_json::json!(null)),
            make_case(serde_json::json!({"param_0": 1}), serde_json::json!(null)),
            make_case(serde_json::json!(null), serde_json::json!(7)),
        ];

        let report = parse_test_results(json, &baseline);
        assert_eq!(
            report.passed, 2,
            "the row that compared no value and the row whose value matched both pass"
        );
        assert_eq!(
            report.failed.len(),
            1,
            "the uncallable input fails its case"
        );
        assert_eq!(
            report.value_assessed, 1,
            "only the third row compared a value"
        );
        assert_eq!(report.values_matched, 1);
        assert!(report.produced_results);
    }

    #[test]
    fn test_parse_test_results_skipped() {
        let baseline = vec![TestCase {
            inputs: serde_json::json!({}),
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];
        let report = parse_test_results("SKIPPED: no baseline file", &baseline);
        assert_eq!(report.passed, 0);
        assert_eq!(report.total, 1);
        assert!(report.failed.is_empty());
        assert_eq!(report.trace_assessed, 0, "a skipped run assesses nothing");
        assert!(!report.produced_results);
    }

    #[test]
    fn test_parse_test_results_json() {
        let json = r#"[{"expected": 42, "actual": 42, "passed": true, "error": null}, {"expected": 100, "actual": 99, "passed": false, "error": "expected 100, got 99"}]"#;

        let baseline = vec![
            TestCase {
                inputs: serde_json::json!({"x": 10}),
                expected_return: serde_json::json!(42),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
            TestCase {
                inputs: serde_json::json!({"x": 20}),
                expected_return: serde_json::json!(100),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
        ];

        let report = parse_test_results(json, &baseline);
        assert_eq!(report.passed, 1);
        assert_eq!(report.total, 2);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].test_index, 1);
        assert_eq!(report.failed[0].error, "expected 100, got 99");
        assert_eq!(
            report.trace_assessed, 0,
            "results without the trace dimension read as unassessed"
        );
        assert!(report.produced_results);
        assert_eq!(
            (report.value_assessed, report.values_matched),
            (2, 1),
            "rows that predate the value_assessed flag compared a value unconditionally"
        );
    }

    #[test]
    fn test_parse_test_results_reports_global_divergences_by_typed_kind() {
        // A failing test whose case expects global side effects
        // surfaces them on the FailedTest as named kinds — the
        // divergence on global handling is machine-comparable data,
        // not prose the consumer has to parse.
        let json =
            r#"[{"expected": 42, "actual": 7, "passed": false, "error": "expected 42, got 7"}]"#;

        let baseline = vec![TestCase {
            inputs: serde_json::json!({"x": 10}),
            expected_return: serde_json::json!(42),
            expected_side_effects: vec![
                calxgloss_types::SideEffect {
                    kind: calxgloss_types::SideEffectKind::GlobalWrite,
                    detail: "DAT_180064e80".to_string(),
                },
                calxgloss_types::SideEffect {
                    kind: calxgloss_types::SideEffectKind::GlobalRead,
                    detail: "g_counter".to_string(),
                },
            ],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let report = parse_test_results(json, &baseline);
        assert_eq!(report.passed, 0);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            report.failed[0].expected_side_effects, baseline[0].expected_side_effects,
            "the failure carries the typed expectations through"
        );
    }

    #[test]
    fn test_parse_test_results_carries_the_trace_divergence_as_typed_data() {
        // A failed case whose runner report carries the ordered traces and
        // the named divergence position lands on the FailedTest as typed
        // data, not only inside the prose error string.
        let json = r#"[{"test_index":0,"expected":7,"actual":7,"passed":false,"error":"API-call trace divergence at position 1: expected [blit, present], got [present, blit]","expected_api_calls":["blit","present"],"actual_api_calls":["present","blit"],"trace_divergence_index":1,"trace_assessed":true}]"#;

        let baseline = vec![TestCase {
            inputs: serde_json::json!(null),
            expected_return: serde_json::json!(7),
            expected_side_effects: vec![],
            expected_api_calls: vec!["blit".to_string(), "present".to_string()],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let report = parse_test_results(json, &baseline);
        assert_eq!(
            report.passed, 0,
            "a matching value on a diverging path fails"
        );
        assert_eq!(report.trace_assessed, 1, "the dimension was assessed");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            report.failed[0].error,
            "API-call trace divergence at position 1: expected [blit, present], got [present, blit]",
            "the failure names the trace divergence at the position"
        );
        assert_eq!(
            report.failed[0].actual_api_calls,
            ["present".to_string(), "blit".to_string()],
            "the actual trace travels beside the expected one"
        );
        assert_eq!(
            report.failed[0].expected_api_calls,
            ["blit".to_string(), "present".to_string()]
        );
        assert_eq!(report.failed[0].trace_divergence_index, Some(1));
    }

    #[test]
    fn test_stubs_all_produces_valid_rust() {
        let stubs = Stubs::all();
        assert!(!stubs.is_empty());
        assert!(stubs.contains("pub trait"));
    }

    #[test]
    fn test_generate_test_harness_structure() {
        let dir = std::env::temp_dir().join("calxgloss_verify_harness");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![
            TestCase {
                inputs: serde_json::json!([10, 20]),
                expected_return: serde_json::json!(30),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
            TestCase {
                inputs: serde_json::json!([0, 0]),
                expected_return: serde_json::json!(0),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
        ];

        let harness =
            verifier.generate_test_harness("MyFunc", &tests, "pub fn MyFunc(x: u32) -> u32 { x }");
        assert!(harness.contains("fn main()"));
        assert!(harness.contains("fn call_function"));
        assert!(
            harness.contains("Value::Array(arr) if arr.len() == 2 => to_json(MyFunc(json_arg(&arr[0], 0)?, json_arg(&arr[1], 1)?)),"),
            "the runner calls the unit by name; a repeated shape gets one arm, not two: {harness}"
        );
        assert!(
            harness.contains("std::panic::catch_unwind"),
            "a panicking unit fails its case, never the whole run"
        );
        assert!(
            harness.contains("value_assessed"),
            "every row states whether a value was ever compared"
        );
        assert!(
            !harness.contains("named parameters not supported"),
            "the refusal-to-call sentinel is gone"
        );

        // A suite feeding a named object — the shape the harness used to
        // refuse — keeps one honest fallback arm that fails the case.
        let object_case = vec![TestCase {
            inputs: serde_json::json!({"param_0": 1}),
            expected_return: serde_json::json!(null),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];
        let harness =
            verifier.generate_test_harness("MyFunc", &object_case, "pub fn MyFunc() -> u32 { 0 }");
        assert!(
            harness.contains("gives MyFunc no callable arguments"),
            "an uncallable input fails its case by name, not by sentinel value"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_array() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!([1, 2, 3]),
            expected_return: serde_json::json!(6),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let patterns = verifier.generate_input_patterns("Sum3", &tests, false);
        assert!(
            patterns.contains("Value::Array(arr) if arr.len() == 3 => to_json(Sum3(json_arg(&arr[0], 0)?, json_arg(&arr[1], 1)?, json_arg(&arr[2], 2)?)),"),
            "a 3-slot case dispatches to the unit by name with three coerced arguments: {patterns}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_null() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns_null");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::Value::Null,
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let patterns = verifier.generate_input_patterns("Tick", &tests, false);
        assert!(
            patterns.contains("Value::Null => to_json(Tick()),"),
            "a null-input case calls the unit named by the verify request: {patterns}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsafe_marker_counts_only_at_the_named_units_own_definition() {
        let dir = std::env::temp_dir().join("calxgloss_verify_unsafe_flag");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();

        // The unit's own unsafe definition is what needs the unsafe call block.
        assert!(verifier.unit_is_unsafe("Tick", "pub unsafe fn Tick() -> u32 { 0 }"));
        assert!(verifier.unit_is_unsafe("Tick", "unsafe fn Tick<T>(x: T) {{ }}"));
        // A different unit whose name merely starts with this one's is not
        // this unit's definition: an old repeated strip read `TickTick(` as
        // unit `Tick` and wrapped that unit's safe calls in unsafe blocks.
        assert!(!verifier.unit_is_unsafe("Tick", "unsafe fn TickTick() -> u32 { 0 }"));
        // A plain call of an unsafe name is not a definition line either,
        // and a safe definition keeps plain calls.
        assert!(!verifier.unit_is_unsafe("Tick", "let r = unsafe { Tick() };"));
        assert!(!verifier.unit_is_unsafe("Tick", "pub fn Tick() -> u32 { 0 }"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_number() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns_num");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!(42),
            expected_return: serde_json::json!(42),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let patterns = verifier.generate_input_patterns("Half", &tests, false);
        assert!(
            patterns.contains("Value::Number(_) => to_json(Half(json_arg(inputs, 0)?)),"),
            "a bare-number input calls the unit with one coerced argument: {patterns}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires cargo binary"]
    async fn test_compilation_result_from_simple_code() {
        let dir = std::env::temp_dir().join("calxgloss_verify_simple");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();

        let result = verifier
            .compile(
                "test.dll",
                "SimpleFunc",
                "pub fn simple_func(x: i32) -> i32 { x * 2 }",
            )
            .await;

        if let Ok(cr) = result {
            assert!(cr.success, "Simple function should compile successfully");
            assert!(cr.errors.is_empty());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires cargo binary"]
    async fn test_compilation_result_from_code_with_errors() {
        let dir = std::env::temp_dir().join("calxgloss_verify_errors");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();

        let result = verifier
            .compile(
                "test.dll",
                "BadFunc",
                "pub fn bad_func() -> i32 { \"not an int\" }",
            )
            .await;

        if let Ok(cr) = result {
            assert!(
                !cr.success,
                "Function with type mismatch should not compile"
            );
            assert!(!cr.errors.is_empty());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scaffold_project_creates_files() {
        let dir = std::env::temp_dir().join("calxgloss_verify_test_scaffold");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let project_dir = dir.join("test_scaffold_project");

        let verifier = Verifier::new(&project_dir).unwrap();

        let project = verifier
            .scaffold_project(
                "test.dll",
                "MyFunc",
                "pub fn my_func(x: i32) -> i32 { x + 1 }",
            )
            .unwrap();

        assert!(project.exists());
        assert!(project.join("Cargo.toml").exists());
        assert!(project.join("src").join("lib.rs").exists());

        let lib_rs = std::fs::read_to_string(project.join("src").join("lib.rs")).unwrap();
        // Traits are now in the pal module, not directly in lib.rs
        assert!(lib_rs.contains("use pal::*") || lib_rs.contains("pub trait"));
        assert!(lib_rs.contains("pub fn my_func"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scaffold_test_project_creates_files() {
        let dir = std::env::temp_dir().join("calxgloss_verify_scaffold_test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!([1, 2]),
            expected_return: serde_json::json!(3),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];

        let project = verifier
            .scaffold_test_project(
                "test.dll",
                "MyFunc",
                "pub fn my_func(x: i32, y: i32) -> i32 { x + y }",
                &tests,
            )
            .unwrap();

        assert!(project.exists());
        assert!(project.join("Cargo.toml").exists());
        assert!(project.join("src").join("lib.rs").exists());
        assert!(project.join("src").join("main.rs").exists());
        assert!(project.join("baseline.json").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Shim verification tests ----

    #[test]
    fn test_parse_test_line_ok() {
        let line = "test shim_tests::test_direct3dcreate9_params ... ok";
        let parsed = parse_test_line(line).unwrap();
        assert_eq!(parsed.name, "shim_tests::test_direct3dcreate9_params");
        assert!(parsed.is_ok);
    }

    #[test]
    fn test_parse_test_line_failed() {
        let line = "test shim_tests::test_present_params ... FAILED";
        let parsed = parse_test_line(line).unwrap();
        assert_eq!(parsed.name, "shim_tests::test_present_params");
        assert!(!parsed.is_ok);
    }

    #[test]
    fn test_parse_test_line_ignored() {
        let line = "test shim_tests::test_ignored ... ignored";
        let parsed = parse_test_line(line);
        assert!(parsed.is_none());
    }

    #[test]
    fn test_parse_test_line_non_test() {
        let line = "this is not a test output";
        let parsed = parse_test_line(line);
        assert!(parsed.is_none());
    }

    #[test]
    fn a_runner_death_signal_is_recognized_from_cargos_wording() {
        // cargo's real wording for a runner killed by the unit crashing.
        assert!(parse::runner_death_signal(
            "error: failed to run bin `scratch_verify` (target/debug/scratch_verify)\
             \nCaused by:\n  process didn't exit successfully: `...` (signal: 11, SIGSEGV: invalid memory reference)"
        ));
        assert!(parse::runner_death_signal(
            "error: test failed, to rerun pass `--test integration`\n\
             (signal: 6, SIGABRT: process abort signal)"
        ));
        // Ordinary failures and near-misses never read as a death signal.
        assert!(!parse::runner_death_signal(
            "test result: FAILED. 3 passed; 1 failed"
        ));
        assert!(!parse::runner_death_signal(
            "error: could not compile `scratch` (bin \"runner\") due to 1 previous error"
        ));
    }

    #[test]
    fn a_partial_suite_stops_when_the_runner_died_short_of_its_cases() {
        let cases = vec![
            TestCase {
                inputs: serde_json::json!([null]),
                expected_return: serde_json::json!(null),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
            TestCase {
                inputs: serde_json::json!([null]),
                expected_return: serde_json::json!(null),
                expected_side_effects: vec![],
                expected_api_calls: vec![],
                origin: calxgloss_types::CaseOrigin::Generated,
            },
        ];
        // One row printed of two cases, and cargo's fatal-signal line: the
        // unit crashed the runner on the second case.
        let output = "[{\"test_index\":0,\"expected\":null,\"actual\":7,\"passed\":true,\
                      \"error\":null,\"expected_api_calls\":[],\"actual_api_calls\":[],\
                      \"trace_divergence_index\":null,\"value_assessed\":false}]\n\
                      error: process didn't exit successfully: `...` (signal: 11, SIGSEGV: invalid memory reference)";
        let report = parse::parse_test_results(output, &cases);
        assert!(report.produced_results, "the printed row is a real result");
        assert!(report.incomplete, "the suite did not finish");
        assert_eq!(report.total, 1, "only one row is claimed");
    }

    #[test]
    fn a_fatal_signal_run_before_any_row_reads_as_the_units_crash_not_a_harness_fault() {
        // The shape verify()'s no-rows + fatal-signal arm reads: a test
        // project that built, ran, and died on a fatal signal before
        // printing any row. It is the unit's failing test — never a harness
        // fault and never a pass — and with no rows printed, no evidence
        // says which case the runner broke on, so the failure record names
        // no inputs and claims no return.
        let cases = vec![TestCase {
            inputs: serde_json::json!([null, 1]),
            expected_return: serde_json::json!(null),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: calxgloss_types::CaseOrigin::Generated,
        }];
        let output = "error: process didn't exit successfully: `target/debug/runner` \
                      (signal: 11, SIGSEGV: invalid memory reference)";
        let report = parse::parse_test_results(output, &cases);
        assert!(
            parse::runner_death_signal(output),
            "cargo's death line reads as a fatal signal"
        );
        assert!(!report.produced_results, "the runner printed no rows");
        // The record the arm files: the crash names itself; the crashed
        // case stays unnamed because nothing was printed to attribute it.
        let failure = parse::runner_died_before_first_row();
        assert!(failure.error.contains("crashed the runner"));
        assert!(
            failure.error.contains("crashed case is unknown"),
            "the record admits it cannot name the crashed case: {:?}",
            failure.error
        );
        assert!(
            failure.inputs.is_null(),
            "no case is claimed as the crashed one: {failure:?}"
        );
        assert_eq!(
            failure.actual,
            serde_json::Value::String("runner died on a fatal signal".to_string())
        );
    }
}
