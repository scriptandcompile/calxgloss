//! Experiment logging for prompt variant tracking.

/// Log a prompt variant experiment entry for analysis.
///
/// Persists the entry to `re/analysis/prompt_strategy_log.json` via the
/// [`PromptStrategyLogger`](calxgloss_analysis::PromptStrategyLogger).
/// If the workspace path is `None`, the entry is silently discarded.
///
/// # Arguments
///
/// * `dll_name` — The DLL filename (e.g., `"game_logic.dll"`).
/// * `strategy` — The retry strategy used (e.g., `"compile_fix"`, `"test_fix"`).
/// * `success` — Whether this attempt succeeded.
/// * `attempt_num` — The attempt number (1-based).
/// * `workspace` — The workspace root path for the log file. `None` to skip logging.
pub fn log_prompt_variant_experiment(
    dll_name: &str,
    strategy: &str,
    success: bool,
    attempt_num: u32,
    workspace: Option<&std::path::Path>,
) {
    let Some(ws) = workspace else {
        return;
    };

    let dll_category = calxgloss_analysis::classify_dll_name(dll_name);
    let entry = calxgloss_types::PromptStrategyEntry::new(
        dll_name,
        dll_category,
        strategy,
        success,
        attempt_num,
    );

    let logger = calxgloss_analysis::PromptStrategyLogger::new(ws);
    logger.record(entry);
}
