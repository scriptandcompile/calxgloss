//! The `auto` command — reads the project's state and runs the next
//! step.
//!
//! It handles classification, batch translation, and the interactive
//! file-selection flow.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss::PipelineRunRequest;
use calxgloss::ProgressEvent;
use calxgloss::RunScope;
use calxgloss::RunTarget;
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_translator::AcceptedAttemptSource;
use calxgloss_translator::assembly::BinaryTarget;
use calxgloss_translator::assembly::assemble;
use tracing::{info, warn};

use crate::commands::classify::handle_classify;
use crate::commands::run_options::{AutoRunOptions, PassPlumbing, RunControls};
use crate::commands::{classification_record_exists, scan_targets};
use crate::utils::*;

/// What one binary pass did against what it set out to do (issue #220).
///
/// "Incomplete" is derived, never stored: a binary is incomplete when its
/// last pass attempted fewer units than it planned — it ended early at a
/// pause boundary — or when it never ran at all. The queue loop reads this
/// to decide whether a paused binary goes back on the worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassOutcome {
    /// Units the pass enumerated and set out to translate.
    pub planned: usize,
    /// Units the batch actually attempted before the pass ended.
    pub attempted: usize,
}

impl PassOutcome {
    /// The pass ended before finishing its plan — a binary pause (or a
    /// run-level stop) cut it short at a unit boundary.
    pub fn ended_early(&self) -> bool {
        self.attempted < self.planned
    }
}

/// The pipeline's view of the git history for carry-over seeding
/// (issue #326): where an accepted (merged) translation's code lives.
///
/// The translator crate never touches git, so the CLI layer implements the
/// port — one `GitManager::open` per lookup keeps the handle short-lived
/// (the pass itself holds its own manager and may have a branch checked
/// out; opening fresh reads history without disturbing it). Every command
/// that uses this seam attaches this port when git is in play (issue #299).
pub(crate) struct GitAcceptedAttempts {
    pub(crate) workspace: PathBuf,
}

impl AcceptedAttemptSource for GitAcceptedAttempts {
    fn accepted_attempt(&self, binary: &str, function: &str) -> Option<(u32, String)> {
        let git = GitManager::open(&self.workspace).ok()?;
        git.accepted_attempt_translation(binary, function)
    }
}

/// Run batch translation for a single DLL.
///
/// This function runs one binary's translation pass: the analysis engine
/// load, function enumeration and scope filtering, git operations,
/// assembling the complete pass from the run description carried by its
/// `PassPlumbing` argument (issue #325), and result reporting.
/// `handle_auto` calls it; `live` reaches it through `handle_auto`.
///
/// The Kuna engine is loaded per pass from `binary_path` (issue #214) —
/// the file named for the pass is the program the scan reads, so there is
/// no server to attach to and no wrong-program guard to run.
///
/// `scope` restricts which functions re-enter the translation queue based on
/// the recorded attempt history (see [`scope_functions`]);
/// [`RunScope::AllFunctions`] keeps the plain behaviour.
///
/// The return reports the pass as [`PassOutcome`] — units attempted against
/// units planned — so the queue loop can derive whether it ended early
/// (issue #220).
pub async fn run_translation_for_dll(
    binary: &str,
    binary_path: &Path,
    scope: RunScope,
    plumbing: &PassPlumbing<'_>,
) -> Result<PassOutcome> {
    let PassPlumbing {
        workspace,
        settings,
        skip_git,
        spec: base_spec,
        run,
    } = plumbing;
    let events = run.events;
    let workspace = *workspace;
    let settings = *settings;

    // Announce the per-binary pass so the dashboard can mark this binary as
    // being worked on before any unit event exists — function enumeration,
    // analysis recovery, and test generation can run for minutes first.
    if let Some(ev) = events {
        ev.emit(ProgressEvent::BatchStarted {
            binary: binary.to_string().into(),
        });
    }

    // Kuna is the only analysis engine (issue #214): the scan source is
    // loaded in-process from the binary file before anything is listed —
    // the file named for this pass is the program the scan reads.
    let kuna = load_kuna_at(settings, binary_path)?;

    // List functions from the analysis engine
    use calxgloss_decomp::ScanSource;
    let summaries = ScanSource::functions(&kuna)
        .await
        .with_context(|| "Failed to list functions from the engine")?;

    if summaries.is_empty() {
        warn!("the engine listed no functions");
        println_content("No functions found in the loaded program.");
        return Ok(PassOutcome {
            planned: 0,
            attempted: 0,
        });
    }

    let function_names: Vec<String> = summaries.into_iter().map(|s| s.name).collect();
    info!(
        count = function_names.len(),
        "Enumerated functions from the engine"
    );

    // W2.3 scope selectors: only-queued / only-failed restrict the queue plan
    // to functions whose recorded attempt history matches, making the filter
    // observable in the batch summary and per-unit events.
    let function_names = scope_functions(binary, workspace, scope, function_names)?;
    if function_names.is_empty() {
        // Still emit the batch summary so the dashboard sees the pass happened.
        if let Some(ev) = events {
            ev.emit(ProgressEvent::BatchSummary {
                binary: binary.to_string().into(),
                total_functions: 0,
                success_count: 0,
                failure_count: 0,
                total_attempts: 0,
                total_tokens: 0,
            });
        }
        info!("Skipping translation for {binary}: no functions match scope {scope}");
        return Ok(PassOutcome {
            planned: 0,
            attempted: 0,
        });
    }

    info!(
        binary = %binary,
        function_count = function_names.len(),
        "Starting batch translation"
    );

    // Initialize output directory
    std::fs::create_dir_all(workspace.join("src").join("modules"))
        .context("Failed to create modules directory")?;

    // The pass description (issue #325): `handle_auto` folded the resolved
    // settings once and layered this run's flags and live control handles
    // on top. The only thing separating one pass from another is the
    // binary it names — its identity for reports and the read-cache key for
    // the batch (issues #105 and #106, the read-cache key and the
    // refresh-cache option, now reach the pass as fields on the spec).
    let mut spec = base_spec.clone();
    spec.target_binary = Some(BinaryTarget {
        name: binary.to_string(),
        path: binary_path.to_path_buf(),
    });

    // Git setup
    let mut git = if !*skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            GitManager::init_repo(workspace, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Carry-over seeding (issue #299): with git in play, the pipeline can
    // ask the branch history whether a paired previous-version twin has an
    // accepted (merged) translation to seed attempt 1 from. With
    // `--skip-git` there is no history to ask, and every unit is
    // translated fresh.
    if let Some(git_manager) = git.as_ref() {
        spec.accepted_attempt_source = Some(std::sync::Arc::new(GitAcceptedAttempts {
            workspace: git_manager.repo_path().to_path_buf(),
        }));
    }

    // Assemble the complete pass once from the description (issue #325):
    // the assembly seam builds the LLM client from the folded endpoint
    // description, the detector, testgen, the verifier, the retry ladder,
    // and every injected handle — the command no longer performs the
    // `with_*` builder dance itself.
    let pass = assemble(&spec, &kuna)
        .await
        .with_context(|| format!("Failed to assemble the translation pass for {binary}"))?;

    // Run batch translation with an inline callback that handles git operations
    // for each function immediately after it completes.
    //
    // This enables incremental git commits: as soon as a function's translation
    // pipeline finishes (including retries), the result is written, committed,
    // and merged — before the next function even starts.
    let batch_result = pass
        .pipeline
        .batch_translate(
            binary,
            &function_names,
            &pass.retry,
            &pass.verifier,
            Some(&mut |_dll, _function, func_result| {
                // A unit with no translated code — failed, or a refused
                // root recorded skipped — has nothing to write or commit.
                let Some(rust_code) = func_result.rust_code.as_ref() else {
                    return true;
                };
                let output_path =
                    workspace.join(GitManager::translated_module_path(&func_result.function));
                if let Err(e) = std::fs::create_dir_all(output_path.parent().unwrap())
                    .context("Failed to create output directory")
                {
                    warn!(error = %e, "Failed to create output directory");
                    return true;
                }
                if let Err(e) = std::fs::write(&output_path, rust_code).with_context(|| {
                    format!(
                        "Failed to write translated code to {}",
                        output_path.display()
                    )
                }) {
                    warn!(error = %e, "Failed to write translated code");
                    return true;
                }

                if let Some(ref mut git_manager) = git
                    && let Ok(branch_result) = git_manager.create_branch(
                        binary,
                        &func_result.function,
                        1,
                        Some(&BranchCreationPolicy::Warn(DependencyPolicy {
                            category: DllCategory::ProjectSpecific,
                            crate_replacement: None,
                        })),
                    )
                {
                    let branch_info = &branch_result.branch;
                    print_git_status(branch_info, false);

                    if let Some(output_path_str) = output_path.to_str()
                        && let Ok(_commit) = git_manager.commit(
                            branch_info,
                            // Carry-over provenance (issue #299): when attempt
                            // 1 was seeded from an accepted translation of a
                            // paired previous-version function, the commit
                            // says so and names the source. A fresh unit's
                            // message is unchanged, byte for byte.
                            &match func_result.carry_over.as_ref() {
                                Some(seed) => format!(
                                    "re/auto/{}: translate {} (batch attempt, {})",
                                    func_result.function,
                                    binary,
                                    seed.commit_note()
                                ),
                                None => format!(
                                    "re/auto/{}: translate {} (batch attempt)",
                                    func_result.function, binary
                                ),
                            },
                            &[output_path_str],
                        )
                        && let Ok(merge_result) = git_manager.merge_to_main(branch_info)
                    {
                        match &merge_result {
                            calxgloss_git::MergeResult::Merged { merge_hash } => {
                                info!(hash = %merge_hash, "Translation accepted and merged");
                            }
                            calxgloss_git::MergeResult::AlreadyUpToDate => {
                                info!("Branch was already up to date with main");
                            }
                            calxgloss_git::MergeResult::Conflicts {
                                conflicted_files,
                                error,
                            } => {
                                warn!(files = ?conflicted_files, error = %error, "Merge conflicts");
                            }
                        }
                        func_result.branch = Some(branch_info.clone());
                    }
                }
                true
            }),
        )
        .await
        .with_context(|| format!("Batch translation failed for DLL: {}", binary))?;

    print_batch_summary(&batch_result);

    // Emit batch summary event for live mode
    if let Some(events) = events {
        let total_attempts: usize = batch_result
            .results
            .iter()
            .map(|r| r.retry_result.attempts.len())
            .sum();
        let total_tokens: usize = batch_result
            .results
            .iter()
            .flat_map(|r| &r.retry_result.attempts)
            .filter_map(|a| a.tokens_used)
            .sum();
        events.emit(ProgressEvent::BatchSummary {
            binary: binary.to_string().into(),
            total_functions: batch_result.total_count(),
            success_count: batch_result.success_count(),
            failure_count: batch_result.failure_count(),
            total_attempts,
            total_tokens,
        });
    }

    if batch_result.all_success() {
        println!(
            "\n  {}",
            green_bold(&format!(
                "Batch complete: all {} functions translated successfully",
                batch_result.total_count()
            ))
        );
    } else if batch_result.any_success() {
        println!(
            "\n  {}",
            yellow_bold(&format!(
                "Batch complete: {} succeeded, {} failed out of {} functions",
                batch_result.success_count(),
                batch_result.failure_count(),
                batch_result.total_count()
            ))
        );
    } else {
        println!(
            "\n  {}",
            red_bold(&format!(
                "Batch complete: all {} functions failed",
                batch_result.total_count()
            ))
        );
    }

    println!();
    println_content("To review, run: calxgloss dashboard");
    println_content(
        "To see the web UI (requires server feature): cargo run --features server --bin web_server",
    );
    println!();

    // The queue loop derives "incomplete" from this: a batch that attempted
    // fewer units than the pass planned ended early (issue #220).
    Ok(PassOutcome {
        planned: function_names.len(),
        attempted: batch_result.results.len(),
    })
}

/// Handle the `auto` subcommand: detects project state and runs classification
/// then batch translation.
///
/// Ensure the workspace is a git repository before the run's slow steps
/// begin (issue #123). A clean start otherwise leaves the dashboard — the
/// only visible surface during the analysis engine load — reporting "Not
/// a Git repository" until translation finally reaches its own git setup.
/// Idempotent: `Repository::init` on an existing repo keeps its history.
fn ensure_workspace_repo(workspace: &Path, skip_git: bool) -> Result<()> {
    if skip_git {
        return Ok(());
    }
    GitManager::init_repo(workspace, Some(calxgloss_git::InitConfig::default()))
        .context("Failed to initialize git repository")?;
    Ok(())
}

/// `run` carries the W2.3 start/restart selectors: `target` restricts the run
/// to one binary, `phase=Classify` forces re-classification, and `scope`
/// restricts which functions re-enter the translation queue (see
/// [`scope_functions`]). `None` keeps the plain `auto` behaviour.
pub async fn handle_auto(
    opts: AutoRunOptions<'_>,
    run_controls: RunControls<'_>,
    run: Option<&PipelineRunRequest>,
) -> Result<()> {
    let AutoRunOptions {
        target,
        binaries_arg: binaries,
        all_functions: _all_functions,
        classify_only,
        continue_mode,
        skip_git,
        settings,
        workspace,
        no_callgraph,
        callgraph_cache,
        callgraph_verbose,
        refresh_cache,
    } = opts;
    info!("Auto mode: detecting project state");

    // The phases below read these three by name; the rest of the live
    // controls reach the run through `run_controls` itself.
    let RunControls {
        events,
        stop: _,
        control: _,
        cancellation: _,
        scope_control,
        override_control: _,
        classification_overrides,
    } = run_controls;

    // target_dir is required: it's the directory containing DLLs/EXEs.
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .or_else(|| target.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "target_dir is required.\n\nSet it via:\n  --target-dir <path>\n  [target_dir] in calxgloss.toml\n  CALXGLOSS_TARGET_DIR env var"
        ))?;

    info!(path = ?target_dir, "Auto mode: using target directory");
    info!(path = ?workspace, "Auto mode: using workspace");

    // Discover or accept DLL list
    let dlls = if let Some(ref dll_list) = binaries {
        dll_list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        scan_targets(&target_dir)
    };

    if dlls.is_empty() {
        println!(
            "  {} No DLL/EXE files found in {}.",
            red_bold("✗"),
            target_dir.display()
        );
        println_content(
            "Specify files explicitly: calxgloss auto --binaries \"eqgame.dll,myapp.exe\"",
        );
        anyhow::bail!("No files found");
    }

    // W2.3 target selector: restrict the run to one binary. A name that is
    // not in the discovered set is a clear error, not a silent no-op.
    let dlls = match run.map(|r| &r.target) {
        None | Some(RunTarget::All) => dlls,
        Some(RunTarget::Binary(id)) => {
            let name = id.as_str();
            if !dlls.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                anyhow::bail!(
                    "run target {name} was not found in {}",
                    target_dir.display()
                );
            }
            dlls.into_iter()
                .filter(|d| d.eq_ignore_ascii_case(name))
                .collect()
        }
    };
    // `phase=Classify` re-runs classification even for already-classified
    // binaries; the default phase leaves the detection logic untouched.
    let force_classify = run.is_some_and(|r| r.phase == calxgloss::RunPhase::Classify);

    // The workspace record tree comes first (issue #123): `.git` exists
    // before any scan work, so a clean start never leaves the dashboard
    // warning about an uninitialized workspace.
    ensure_workspace_repo(&workspace, skip_git)?;

    println!();
    hsep_bold();
    println_content(format!(
        "  Calxgloss Auto — {} file(s) found",
        bold(&dlls.len().to_string())
    ));
    hsep();
    println_content("");
    for binary in &dlls {
        println_content(format!(
            "  • {}{}",
            bold(binary),
            if classification_record_exists(&workspace, binary) {
                format!("  [{}] already classified", yellow_bold("done"))
            } else {
                format!("  [{}] needs classification", red_bold("pending"))
            }
        ));
    }
    println_content("");

    // Determine which DLLs are classified and which are not
    let mut classified: Vec<String> = dlls
        .iter()
        .filter(|d| !force_classify && classification_record_exists(&workspace, d))
        .cloned()
        .collect();
    let unclassified: Vec<String> = dlls
        .iter()
        .filter(|d| force_classify || !classification_record_exists(&workspace, d))
        .cloned()
        .collect();

    // Step 1: Classify unclassified files
    if !unclassified.is_empty() {
        println!(
            "  {} Classifying {} unclassified file(s)…",
            cyan_bold("→"),
            bold(&unclassified.len().to_string())
        );
        println_content("");
        handle_classify(
            &unclassified,
            &target_dir,
            &workspace,
            skip_git,
            settings,
            events,
            classification_overrides,
        )
        .await?;
        println_content("");
        if !continue_mode {
            println_content(
                "Classification complete. Review the report above, then run again to translate.",
            );
            println!();
            return Ok(());
        }
        println_content("Classification complete. Starting translation…");

        // Newly classified DLLs are now ready. Add them to the classified
        // list so the translation loop picks them up.
        classified.extend(unclassified);
    }

    // All files are classified
    if classified.is_empty() {
        println_content("No classified files found; nothing to do.");
        return Ok(());
    }

    println!(
        "  {} {} file(s) classified, ready for translation",
        green_bold("✓"),
        bold(&classified.len().to_string())
    );
    println_content("");

    if classify_only {
        println_content("Classification complete. All files are classified.");
        println_content("Re-run without --classify-only to start translation.");
        return Ok(());
    }

    // Refuse Do Not Translate binaries — the .NET managed ones — before
    // any analysis engine load or LLM client (issue #235). Classification
    // above has already recorded the fact; the guard reads the in-force
    // decision — override, then the PE marker, then the record — for
    // every binary about to be translated.
    for binary in &classified {
        guard_managed_binary(&workspace, binary, &target_dir.join(binary))?;
    }

    // The pass description every translation pass runs on (issue #325):
    // the resolved settings folded once (issue #324), this run's call-graph
    // flags, the resolved workspace, and the live control handles layered
    // on. Each pass clones this description, adds the binary it names, and
    // assembles once — so the command body carries no `with_*` builder
    // dance and no per-knob `if let` ladder.
    let mut pass_spec = crate::settings::pipeline_spec(settings)?;
    if pass_spec.llm.is_none() {
        // A translation pass always needs an LLM. When the record holds no
        // endpoint pair, the settings layer's "not configured" guidance —
        // naming every layer that can supply one — is reported instead of
        // the assembly seam's internal `MissingLlm` wording.
        settings.require_llm_url()?;
        settings.require_llm_model()?;
    }
    // The resolved workspace (--workspace > settings > CWD) wins over the
    // record's own value: the flag layer is what the command was handed.
    pass_spec.workspace = workspace.clone();
    pass_spec.no_callgraph = no_callgraph;
    pass_spec.callgraph_cache_dir = callgraph_cache;
    pass_spec.callgraph_verbose = callgraph_verbose;
    pass_spec.refresh_cache = refresh_cache;
    run_controls.apply(&mut pass_spec);

    // Issue #377: the binaries this run targets, captured where the queue is
    // handed over, so the run close can name each target's unknown audit
    // ledger.
    let close_targets: Vec<String>;

    if continue_mode {
        // W2.5: the operator's binary scope filters the queue before the
        // plan is published — an excluded binary never enters the queue,
        // the dashboard, or a translation pass.
        if let Some(sc) = scope_control {
            let plan = sc.scope();
            if !plan.binaries.is_empty() {
                let total = classified.len();
                classified.retain(|b| plan.admits_binary(b));
                let excluded = total - classified.len();
                if excluded > 0 {
                    println_content(format!(
                        "  Binary scope excludes {excluded} of {total} target(s).",
                    ));
                }
                if classified.is_empty() {
                    println_content("No targets left in scope; nothing to translate.");
                    return Ok(());
                }
            }
        }

        // Translate all classified files in sequence (non-interactive).
        println!();
        println!(
            "  {} Translating {} file(s) in sequence…",
            cyan_bold("→"),
            bold(&classified.len().to_string())
        );
        println!();

        // Issue #220: the queue is a worklist — a paused binary is held out,
        // a binary paused mid-pass is re-queued once, and every order change
        // re-publishes the queue plan.
        let pass_plumbing = PassPlumbing {
            settings,
            workspace: &workspace,
            skip_git,
            spec: pass_spec.clone(),
            run: &run_controls,
        };
        close_targets = classified.clone();
        run_binary_worklist(classified, &run_controls, |binary| {
            let target_dir = target_dir.clone();
            let pass_plumbing = pass_plumbing.clone();
            async move {
                run_translation_for_dll(
                    &binary,
                    &target_dir.join(&binary),
                    run.map(|r| r.scope).unwrap_or_default(),
                    &pass_plumbing,
                )
                .await
            }
        })
        .await?;
    } else {
        // Ask which file to translate (interactive mode).
        println!();
        println!("  {} Which file would you like to translate?", bold("?"));
        println!();
        for (i, binary) in classified.iter().enumerate() {
            let num = i + 1;
            println_content(format!("  {}  {}", num, bold(binary)));
        }
        println_content("");
        println_content("Enter a number (or 0 to cancel):");
        print!("  > ");
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let choice: usize = input.trim().parse().unwrap_or(0);

        if choice == 0 || choice > classified.len() {
            println!();
            println_content("Cancelled.");
            return Ok(());
        }

        let binary = &classified[choice - 1];
        close_targets = vec![binary.clone()];
        println!();
        println!(
            "  {} Translating functions from {}…",
            cyan_bold("→"),
            bold(binary)
        );
        println!();

        run_translation_for_dll(
            binary,
            &target_dir.join(binary),
            run.map(|r| r.scope).unwrap_or_default(),
            &PassPlumbing {
                settings,
                workspace: &workspace,
                skip_git,
                spec: pass_spec,
                run: &run_controls,
            },
        )
        .await?;
    }

    // Issue #377: the run close is a claim list, not a quiet queue. Every
    // binary this run translated closes with its unknown audit ledger —
    // open records named by severity, the reviewer's settled rides counted
    // beside them, and a ledger never filed or unreadable printed as
    // *unknown*, never as a clean run. The terminal dashboard's audit
    // section prints the same lines from the same derivation.
    calxgloss_reports::dashboard::print_run_audit_ledger(&workspace, &close_targets);

    Ok(())
}

/// The auto run's binary queue as a worklist (issue #220).
///
/// A binary the operator has paused is **held out** when the queue reaches
/// it: no scan, no pass, no `BatchStarted` — it goes to the back of the
/// worklist and the run moves to the next entry. A binary paused while in
/// flight finishes its pass early (the batch ends at the unit boundary, per
/// issue #219) and is re-queued the same way. Each binary comes back around
/// exactly once: translated if it has been resumed, left incomplete if it is
/// still paused — one retry per pass, never a spin. Whenever the order
/// changes the loop re-publishes [`ProgressEvent::QueuePlanned`] so the
/// dashboard shows the run's real remaining order, not the plan from the
/// first pass.
///
/// The scope handle's **focus** slot (issue #284) is consulted at the same
/// boundary: if the focused binary is among the not-yet-started entries it
/// moves to the front, the plan re-publishes with it there, and the focus
/// is consumed — honored once, never again. A focus naming nothing still in
/// the queue changes nothing and survives until a boundary names it. Focus
/// reorders, it never parallelizes: the run still works one binary at a
/// time.
///
/// `run_pass` runs one binary's translation pass and reports its
/// [`PassOutcome`]; `handle_auto` supplies the real one and tests supply a
/// fake that records which binaries were ever started.
async fn run_binary_worklist<P, Fut>(
    queue: Vec<String>,
    run: &RunControls<'_>,
    run_pass: P,
) -> Result<()>
where
    P: Fn(String) -> Fut,
    Fut: Future<Output = Result<PassOutcome>>,
{
    let RunControls {
        events,
        stop,
        control,
        cancellation: _,
        scope_control,
        override_control: _,
        classification_overrides: _,
    } = run;
    let mut queue: VecDeque<String> = queue.into();
    // Binaries already re-queued once — a second visit while still paused
    // ends that binary's part in the run, so a paused binary can never spin
    // the loop. Keyed lower-case: binary names match case-insensitively
    // (issue #107).
    let mut requeued: HashSet<String> = HashSet::new();

    // Publish the plan before the first pass starts so the dashboard can
    // show the whole queue — in this exact order — not just the binary
    // currently in flight.
    if let Some(ev) = events {
        ev.emit(ProgressEvent::QueuePlanned {
            binaries: queue.iter().cloned().collect(),
        });
    }

    loop {
        if !queue.is_empty() {
            if stop.is_some_and(|s| s.is_stopped()) {
                println!();
                println_content("Stop requested — skipping remaining binaries.");
                println_content("Work completed so far is saved; restart to continue.");
                break;
            }
            // Issue #90: a stop requested through the pipeline control (or a
            // run that already reached a terminal state) also ends the queue
            // between binaries — the pipeline itself halts at unit
            // boundaries, this keeps us from starting the next pass.
            if control.is_some_and(|c| c.state().is_halted()) {
                println!();
                println_content("Pipeline stop requested — skipping remaining binaries.");
                println_content("Work completed so far is saved; restart to continue.");
                break;
            }

            // Issue #284: honor the scope focus at the binary boundary — the
            // same point where pauses are checked. A focused binary among the
            // not-yet-started entries moves to the front and the plan
            // re-publishes with it there; the focus is then consumed, so a
            // restored record never reorders a later run twice. A focus
            // naming nothing in the queue is left alone: it waits for a
            // boundary that names it. Binary names match case-insensitively
            // (issue #107).
            let focused = scope_control.and_then(|sc| sc.focused_binary().map(|focus| (sc, focus)));
            if let Some((sc, focus)) = focused {
                let hoisted = queue
                    .iter()
                    .position(|b| b.eq_ignore_ascii_case(focus.as_str()))
                    .and_then(|idx| queue.remove(idx).map(|focused| (idx, focused)));
                if let Some((idx, focused)) = hoisted {
                    queue.push_front(focused.clone());
                    sc.consume_focus(&focused);
                    if idx != 0 {
                        println_content(format!(
                            "  {} {} is focused — the run works it next.",
                            cyan_bold("→"),
                            bold(&focused)
                        ));
                        if let Some(ev) = events {
                            ev.emit(ProgressEvent::QueuePlanned {
                                binaries: queue.iter().cloned().collect(),
                            });
                        }
                    }
                }
            }
        }

        let Some(binary) = queue.pop_front() else {
            break;
        };

        // Issue #220: a paused binary is held out of the pass — no scan, no
        // units, no BatchStarted — and comes back around exactly once.
        if scope_control.is_some_and(|sc| sc.is_paused(&binary)) {
            let key = binary.to_lowercase();
            if requeued.contains(&key) {
                println_content(format!(
                    "  {} {} is still paused — left incomplete.",
                    yellow_bold("!"),
                    bold(&binary)
                ));
                continue;
            }
            println_content(format!(
                "  {} {} is paused — held out of the queue.",
                yellow_bold("!"),
                bold(&binary)
            ));
            requeued.insert(key);
            queue.push_back(binary);
            if let Some(ev) = events {
                ev.emit(ProgressEvent::QueuePlanned {
                    binaries: queue.iter().cloned().collect(),
                });
            }
            continue;
        }

        println!(
            "  {} Translating functions from {}…",
            cyan_bold("→"),
            bold(&binary)
        );
        println!();
        let outcome = run_pass(binary.clone()).await?;

        // A pass that ended early because its binary was paused mid-flight
        // goes to the back of the worklist, marked incomplete; the pass that
        // comes back around translates it if it has been resumed.
        if outcome.ended_early() && scope_control.is_some_and(|sc| sc.is_paused(&binary)) {
            let key = binary.to_lowercase();
            if requeued.contains(&key) {
                println_content(format!(
                    "  {} {} is still paused — left incomplete.",
                    yellow_bold("!"),
                    bold(&binary)
                ));
            } else {
                println_content(format!(
                    "  {} {} was paused mid-pass — re-queued, incomplete.",
                    yellow_bold("!"),
                    bold(&binary)
                ));
                requeued.insert(key);
                queue.push_back(binary);
                if let Some(ev) = events {
                    ev.emit(ProgressEvent::QueuePlanned {
                        binaries: queue.iter().cloned().collect(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Filter the enumerated functions down to the ones the run scope admits.
///
/// The scope reads the recorded attempt history (`re/analysis/token_usage.json`):
/// a function is *attempted* when it has any recorded attempt for this binary,
/// and *succeeded* when any attempt succeeded.
///
/// * [`RunScope::AllFunctions`] — everything (the plain behaviour).
/// * [`RunScope::OnlyQueued`] — never attempted: the backlog a first run left
///   untouched (skipped by the call-graph plan or blocked by a stop).
/// * [`RunScope::OnlyFailed`] — attempted but never succeeded: the retry set.
///
/// A missing history file means nothing was attempted, so `OnlyQueued` keeps
/// the whole list and `OnlyFailed` keeps none.
pub(crate) fn scope_functions(
    binary: &str,
    workspace: &Path,
    scope: RunScope,
    functions: Vec<String>,
) -> Result<Vec<String>> {
    if scope == RunScope::AllFunctions {
        return Ok(functions);
    }
    let log = calxgloss_analysis::TokenUsageLogger::new(workspace)
        .load()
        .unwrap_or_default();
    let identity = calxgloss_types::BinaryIdentity::new(binary);
    Ok(functions
        .into_iter()
        .filter(|name| {
            let entries: Vec<_> = log
                .entries
                .iter()
                .filter(|e| e.binary == identity && e.function == *name)
                .collect();
            match scope {
                RunScope::OnlyQueued => entries.is_empty(),
                RunScope::OnlyFailed => !entries.is_empty() && !entries.iter().any(|e| e.success),
                RunScope::AllFunctions => true,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::TokenUsageEntry;

    fn sample_functions() -> Vec<String> {
        ["DrawSprite", "DrawVertex", "UpdateGame"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn temp_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp workspace")
    }

    #[test]
    fn ensure_workspace_repo_creates_git_on_a_clean_start() {
        let workspace = temp_workspace();
        ensure_workspace_repo(workspace.path(), false).expect("init workspace repo");
        assert!(workspace.path().join(".git").exists());
        // The repo is usable: opening it back proves the initial commit landed.
        calxgloss_git::GitManager::open(workspace.path()).expect("open initialized repo");
    }

    #[test]
    fn ensure_workspace_repo_is_idempotent_and_keeps_history() {
        let workspace = temp_workspace();
        ensure_workspace_repo(workspace.path(), false).expect("first init");
        // A commit made after the first init (e.g. a classification record)
        // must still be reachable on main after a second ensure.
        {
            let repo = git2::Repository::open(workspace.path()).expect("open");
            let sig = git2::Signature::now("t", "t@t").expect("sig");
            let mut idx = repo.index().expect("index");
            std::fs::write(workspace.path().join("record.json"), "{}").expect("write");
            idx.add_path(Path::new("record.json")).expect("add");
            idx.write().expect("write index");
            let tree_oid = idx.write_tree().expect("tree oid");
            let tree = repo.find_tree(tree_oid).expect("tree");
            let parent = repo.head().expect("head").peel_to_commit().expect("parent");
            repo.commit(
                Some("refs/heads/main"),
                &sig,
                &sig,
                "classification record",
                &tree,
                &[&parent],
            )
            .expect("commit");
        }
        ensure_workspace_repo(workspace.path(), false).expect("second init");
        let repo = git2::Repository::open(workspace.path()).expect("open");
        let main = repo
            .head()
            .expect("head")
            .peel_to_commit()
            .expect("main tip");
        assert!(
            format!("{:?}", main.summary()).contains("classification"),
            "re-ensure must not reset main past the intervening commit: tip is {:?}",
            main.summary()
        );
    }

    #[test]
    fn ensure_workspace_repo_respects_skip_git() {
        let workspace = temp_workspace();
        ensure_workspace_repo(workspace.path(), true).expect("skip is not an error");
        assert!(!workspace.path().join(".git").exists());
    }

    #[test]
    fn scope_all_functions_keeps_everything_without_reading_history() {
        let workspace = temp_workspace();
        let kept = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::AllFunctions,
            sample_functions(),
        )
        .expect("all-functions scope never fails");
        assert_eq!(kept, sample_functions());
    }

    #[test]
    fn scope_filters_follow_the_recorded_attempt_history() {
        let workspace = temp_workspace();
        let logger = calxgloss_analysis::TokenUsageLogger::new(workspace.path());
        // DrawSprite: attempted and succeeded. DrawVertex: attempted, failed
        // twice. UpdateGame: never attempted.
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            100,
            true,
        ));
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawVertex",
            1,
            "initial",
            100,
            false,
        ));
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawVertex",
            2,
            "compile_fix",
            100,
            false,
        ));

        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(queued, ["UpdateGame"]);

        let failed = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyFailed,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(failed, ["DrawVertex"]);
    }

    #[test]
    fn scope_without_history_file_keeps_all_for_queued_and_none_for_failed() {
        let workspace = temp_workspace();
        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("missing history is not an error");
        assert_eq!(queued, sample_functions());

        let failed = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyFailed,
            sample_functions(),
        )
        .expect("missing history is not an error");
        assert!(failed.is_empty());
    }

    #[test]
    fn scope_ignores_other_binaries_history() {
        let workspace = temp_workspace();
        let logger = calxgloss_analysis::TokenUsageLogger::new(workspace.path());
        logger.record(TokenUsageEntry::new(
            "other.dll",
            "DrawSprite",
            1,
            "initial",
            100,
            true,
        ));

        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(queued, sample_functions());
    }

    // --- the auto run's binary worklist (issue #220) ---------------------

    use calxgloss::{ScopeControl, TranslationEvents};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A fake pass's recorder: the binaries it was ever started for. The
    /// scan and the `BatchStarted` event live inside the real pass, so a
    /// binary the fake never saw was never started at all.
    fn started_recorder() -> Rc<RefCell<Vec<String>>> {
        Rc::new(RefCell::new(Vec::new()))
    }

    /// Drain the event channel, collecting every published queue plan.
    fn queue_plans(rx: &mut tokio::sync::broadcast::Receiver<ProgressEvent>) -> Vec<Vec<String>> {
        let mut plans = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(ProgressEvent::QueuePlanned { binaries }) => plans.push(binaries),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return plans,
                Err(e) => panic!("event channel closed: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn paused_binary_is_held_out_and_never_started() {
        let scope = ScopeControl::new();
        scope.pause_binary("b.dll").expect("pause b.dll");
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                async move {
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 3,
                        attempted: 3,
                    })
                }
            },
        )
        .await
        .expect("the run finishes with a paused binary in the queue");

        // b.dll was held out at the first visit and left incomplete at the
        // second — its pass never ran, so no scan and no BatchStarted.
        assert_eq!(*started.borrow(), ["a.dll"]);
        // The hold-out re-published the plan as the run's real remaining
        // order.
        assert_eq!(
            queue_plans(&mut rx),
            vec![vec!["a.dll", "b.dll"], vec!["b.dll"]]
        );
    }

    #[tokio::test]
    async fn held_out_binary_is_translated_when_resumed_before_its_pass_comes_back() {
        let scope = ScopeControl::new();
        scope.pause_binary("b.dll").expect("pause b.dll");
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                let scope = scope.clone();
                async move {
                    if binary == "a.dll" {
                        // The operator resumes b.dll while a.dll's pass runs.
                        scope.resume_binary("b.dll").expect("resume b.dll");
                    }
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 3,
                        attempted: 3,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // b.dll was held out once, then translated when the pass came back
        // around — resuming admitted it again.
        assert_eq!(*started.borrow(), ["a.dll", "b.dll"]);
    }

    #[tokio::test]
    async fn in_flight_paused_binary_is_requeued_once_and_translated_after_resume() {
        let scope = ScopeControl::new();
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                let scope = scope.clone();
                async move {
                    let first_visit = !started.borrow().iter().any(|b| b == &binary);
                    started.borrow_mut().push(binary.clone());
                    if binary == "a.dll" && first_visit {
                        // The operator pauses a.dll while its pass is in
                        // flight: the batch ends at the unit boundary with
                        // units still unattempted (issue #219).
                        scope.pause_binary("a.dll").expect("pause a.dll mid-pass");
                        return Ok(PassOutcome {
                            planned: 5,
                            attempted: 2,
                        });
                    }
                    if binary == "b.dll" {
                        // The operator resumes a.dll while b.dll's pass runs.
                        scope.resume_binary("a.dll").expect("resume a.dll");
                    }
                    Ok(PassOutcome {
                        planned: 5,
                        attempted: 5,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // a.dll ended early, was re-queued once, and translated when the
        // pass came back around after the resume.
        assert_eq!(*started.borrow(), ["a.dll", "b.dll", "a.dll"]);
        // The re-queue re-published the plan in the run's real remaining
        // order.
        assert_eq!(
            queue_plans(&mut rx),
            vec![vec!["a.dll", "b.dll"], vec!["b.dll", "a.dll"]]
        );
    }

    #[tokio::test]
    async fn still_paused_binary_is_left_incomplete_on_its_second_visit() {
        let scope = ScopeControl::new();
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                let scope = scope.clone();
                async move {
                    if binary == "a.dll" && !started.borrow().iter().any(|b| b == "a.dll") {
                        // Paused mid-pass and never resumed: the pass ends
                        // early and the binary is re-queued once.
                        scope.pause_binary("a.dll").expect("pause a.dll mid-pass");
                        started.borrow_mut().push(binary);
                        return Ok(PassOutcome {
                            planned: 5,
                            attempted: 2,
                        });
                    }
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 5,
                        attempted: 5,
                    })
                }
            },
        )
        .await
        .expect("the run finishes while a.dll stays paused");

        // a.dll's second visit found it still paused: left incomplete, never
        // started again, while b.dll's pass and the run itself completed.
        assert_eq!(*started.borrow(), ["a.dll", "b.dll"]);
        assert_eq!(
            queue_plans(&mut rx),
            vec![vec!["a.dll", "b.dll"], vec!["b.dll", "a.dll"]]
        );
    }

    // --- the run's "translate this next" focus (issue #284) --------------

    #[tokio::test]
    async fn focus_hoists_a_queued_binary_at_the_next_boundary() {
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let scope = ScopeControl::new();
        let started = started_recorder();

        run_binary_worklist(
            vec![
                "a.dll".to_string(),
                "b.dll".to_string(),
                "c.dll".to_string(),
            ],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                let scope = scope.clone();
                async move {
                    if binary == "a.dll" {
                        // The operator presses "translate this next" on
                        // c.dll while a.dll's pass runs; the focus names the
                        // identity in its own casing.
                        scope.set_focus("C.DLL").expect("focus c.dll mid-run");
                    }
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 3,
                        attempted: 3,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // c.dll passed right after a.dll — hoisted at the boundary — and the
        // focus was consumed on the way.
        assert_eq!(*started.borrow(), ["a.dll", "c.dll", "b.dll"]);
        assert!(scope.focused_binary().is_none());
        // The initial plan, then the re-published one with the focus at the
        // front of the remaining queue.
        assert_eq!(
            queue_plans(&mut rx),
            vec![vec!["a.dll", "b.dll", "c.dll"], vec!["c.dll", "b.dll"]]
        );
    }

    #[tokio::test]
    async fn focus_naming_no_queued_binary_changes_nothing_and_survives() {
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let scope = ScopeControl::new();
        scope.set_focus("ghost.dll").expect("focus ghost.dll");
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                async move {
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 3,
                        attempted: 3,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // The run is untouched, and the focus waits for a boundary that
        // names it.
        assert_eq!(*started.borrow(), ["a.dll", "b.dll"]);
        assert_eq!(
            scope.focused_binary().map(|f| f.as_str().to_string()),
            Some("ghost.dll".to_string())
        );
        assert_eq!(queue_plans(&mut rx), vec![vec!["a.dll", "b.dll"]]);
    }

    #[tokio::test]
    async fn focus_already_at_the_front_is_consumed_without_re_publishing() {
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let scope = ScopeControl::new();
        scope.set_focus("a.dll").expect("focus a.dll");
        let started = started_recorder();

        run_binary_worklist(
            vec!["a.dll".to_string(), "b.dll".to_string()],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                async move {
                    started.borrow_mut().push(binary);
                    Ok(PassOutcome {
                        planned: 3,
                        attempted: 3,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // The run continues where it was, and the focus does not survive
        // the run.
        assert_eq!(*started.borrow(), ["a.dll", "b.dll"]);
        assert!(scope.focused_binary().is_none());
        // Only the initial plan was published — hoisting a binary already
        // at the front changes nothing, so nothing is re-published.
        assert_eq!(queue_plans(&mut rx), vec![vec!["a.dll", "b.dll"]]);
    }

    #[tokio::test]
    async fn paused_in_flight_binary_yields_to_a_focused_binary_and_re_queues_once() {
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let scope = ScopeControl::new();
        let started = started_recorder();

        run_binary_worklist(
            vec![
                "a.dll".to_string(),
                "b.dll".to_string(),
                "c.dll".to_string(),
            ],
            &RunControls {
                events: Some(&events),
                scope_control: Some(&scope),
                ..RunControls::default()
            },
            |binary| {
                let started = started.clone();
                let scope = scope.clone();
                async move {
                    let first_visit = !started.borrow().iter().any(|b| b == &binary);
                    started.borrow_mut().push(binary.clone());
                    if binary == "a.dll" && first_visit {
                        // a.dll is paused mid-pass (issue #219) while the
                        // operator focuses c.dll.
                        scope.pause_binary("a.dll").expect("pause a.dll mid-pass");
                        scope.set_focus("c.dll").expect("focus c.dll mid-pass");
                        return Ok(PassOutcome {
                            planned: 5,
                            attempted: 2,
                        });
                    }
                    if binary == "c.dll" {
                        // The operator resumes a.dll while c.dll's pass runs.
                        scope.resume_binary("a.dll").expect("resume a.dll");
                    }
                    Ok(PassOutcome {
                        planned: 5,
                        attempted: 5,
                    })
                }
            },
        )
        .await
        .expect("the run finishes");

        // The focused c.dll came first after a.dll's early end, and the
        // still-paused a.dll kept its re-queued-once place at the back —
        // translated on its second visit once resumed.
        assert_eq!(*started.borrow(), ["a.dll", "c.dll", "b.dll", "a.dll"]);
        // Initial plan; a.dll's re-queue; then the focus hoist re-publishes
        // the remaining order.
        assert_eq!(
            queue_plans(&mut rx),
            vec![
                vec!["a.dll", "b.dll", "c.dll"],
                vec!["b.dll", "c.dll", "a.dll"],
                vec!["c.dll", "b.dll", "a.dll"],
            ]
        );
        assert!(scope.focused_binary().is_none());
    }

    // ─── The run close names its claims (issue #377) ───────────────────

    /// Stage a classification record so the binary reads as classified.
    fn stage_classification(workspace: &std::path::Path, binary: &str) {
        let dir = workspace.join("re").join("classify");
        std::fs::create_dir_all(&dir).expect("classify dir");
        std::fs::write(dir.join(format!("{binary}.json")), "{}").expect("record");
    }

    #[tokio::test]
    async fn the_auto_run_reaches_its_close_and_hands_the_targets_to_the_ledger() {
        // The whole handler runs: both binaries read as classified, the
        // worklist never starts a pass (the stop signal is already stopped
        // at the first queue boundary — no scan, no LLM), and the run close
        // runs the audit-ledger derivation over both named targets. With no
        // ledger filed the derivation degrades every binary to unknown and
        // never fails the close; the section's own lines are pinned in the
        // reports crate's audit tests.
        let ws = temp_workspace();
        stage_classification(ws.path(), "game_logic.dll");
        stage_classification(ws.path(), "no_ledger.dll");
        calxgloss_types::save_json(
            &calxgloss_types::unknown_ledger_path(
                ws.path(),
                &calxgloss_types::BinaryIdentity::from("game_logic.dll"),
            ),
            &calxgloss_types::UnknownLedger {
                binary: calxgloss_types::BinaryIdentity::from("game_logic.dll"),
                filed_at: 1_700_000_000,
                records: Some(Vec::new()),
            },
        )
        .expect("file empty ledger");

        let settings = {
            let layers = calxgloss_config::Layers {
                file: calxgloss_config::FileConfig {
                    llm: calxgloss_config::LlmSection {
                        url: Some("http://127.0.0.1:9/v1".into()),
                        model: Some("test-model".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            };
            let loaded = calxgloss_config::LoadedConfig {
                file: layers.file.clone(),
                path: None,
                searched: vec![std::path::PathBuf::from("calxgloss.toml")],
            };
            crate::Settings::resolve(&layers, calxgloss_config::FileConfig::default(), &loaded)
        };

        let stop = calxgloss_types::StopSignal::new();
        stop.stop();

        handle_auto(
            AutoRunOptions {
                target: Some(ws.path().to_path_buf()),
                binaries_arg: Some("game_logic.dll,no_ledger.dll".to_string()),
                all_functions: false,
                classify_only: false,
                continue_mode: true,
                skip_git: true,
                settings: &settings,
                workspace: ws.path().to_path_buf(),
                no_callgraph: true,
                callgraph_cache: None,
                callgraph_verbose: false,
                refresh_cache: false,
            },
            RunControls {
                stop: Some(&stop),
                ..RunControls::default()
            },
            None,
        )
        .await
        .expect("the run reaches its close, ledger degradation and all");
    }
}
