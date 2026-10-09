//! Dashboard summary computations (issue #66): binary category counts,
//! aggregate quality metrics, and token-consumption totals.
//!
//! All three follow the honesty rule used across the dashboard: data that
//! does not exist is reported as absent (`null` / zero counts), never as a
//! fabricated value.

use std::path::Path;

use calxgloss_types::{DllCategory, TokenUsageLog, UnitOfWork};

use super::super::types::{CategoryCount, QualitySummary, TokenUsageSummary};
use super::process::{load_json_or_default, token_usage_log_path};

/// The six [`DllCategory`] variants, in the order the dashboard displays
/// them.
pub const CATEGORY_ORDER: [DllCategory; 6] = [
    DllCategory::WindowsOs,
    DllCategory::MicrosoftSdk,
    DllCategory::KnownThirdParty,
    DllCategory::ProjectSpecific,
    DllCategory::UnknownThirdParty,
    DllCategory::RuntimeLibrary,
];

/// Counts the workspace's classified binaries per category.
///
/// Reads every `re/classify/*.json` artifact and tallies its `category`
/// field. All six categories are always present in the result (count 0
/// when nothing is classified into them) so the frontend can render a
/// stable set of cards. Files with a missing, corrupt, or unrecognised
/// category are skipped rather than guessed at.
pub fn compute_binary_categories(repo_path: &Path) -> Vec<CategoryCount> {
    let classify_dir = repo_path.join("re").join("classify");
    let mut counts = vec![0_usize; CATEGORY_ORDER.len()];

    if let Ok(entries) = std::fs::read_dir(&classify_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(category) = read_classification_category(&path)
                && let Some(slot) = CATEGORY_ORDER.iter().position(|c| *c == category)
            {
                counts[slot] += 1;
            }
        }
    }

    CATEGORY_ORDER
        .iter()
        .zip(counts)
        .map(|(category, count)| CategoryCount {
            category: category.clone(),
            count,
        })
        .collect()
}

/// Reads the `category` field of one classification artifact, returning it
/// only when it names a known [`DllCategory`] variant.
fn read_classification_category(path: &Path) -> Option<DllCategory> {
    let content = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    serde_json::from_value(value.get("category")?.clone()).ok()
}

/// Aggregates quality metrics over the dashboard's units.
///
/// Each metric is `None` when no unit carries the underlying data — the
/// frontend renders `—` rather than a fabricated zero. Pass rates are
/// weighted by test count across units (sum of passed / sum of total), not
/// an average of per-unit ratios, so a unit with 1/1 test does not
/// outweigh one with 20/25.
pub fn compute_quality_summary(units: &[UnitOfWork]) -> QualitySummary {
    let mut confidence_sum = 0.0_f64;
    let mut confidence_count = 0_usize;
    let mut baseline_passed = 0_u64;
    let mut baseline_total = 0_u64;
    let mut verification_passed = 0_u64;
    let mut verification_total = 0_u64;

    for unit in units {
        if let Some(confidence) = unit.unit_confidence {
            confidence_sum += f64::from(confidence);
            confidence_count += 1;
        }
        if let (Some(passed), Some(total)) = (unit.baseline_tests_passed, unit.baseline_tests_total)
        {
            baseline_passed += passed as u64;
            baseline_total += total as u64;
        }
        if let (Some(passed), Some(total)) = (
            unit.verification_tests_passed,
            unit.verification_tests_total,
        ) {
            verification_passed += passed as u64;
            verification_total += total as u64;
        }
    }

    QualitySummary {
        avg_unit_confidence: (confidence_count > 0)
            .then(|| (confidence_sum / confidence_count as f64) as f32),
        baseline_pass_rate: (baseline_total > 0)
            .then(|| (baseline_passed as f64 / baseline_total as f64) as f32),
        verification_pass_rate: (verification_total > 0)
            .then(|| (verification_passed as f64 / verification_total as f64) as f32),
    }
}

/// Totals token consumption from the pipeline's usage log.
///
/// Returns `None` when the log is missing, corrupt, or empty — the token
/// budget visual then says "no usage recorded" instead of showing a
/// fabricated zero.
pub fn compute_token_usage(repo_path: &Path) -> Option<TokenUsageSummary> {
    let log = load_json_or_default::<TokenUsageLog>(&token_usage_log_path(repo_path));
    if log.entries.is_empty() {
        return None;
    }

    let mut total_tokens = 0_u64;
    let mut successful_tokens = 0_u64;
    let mut failed_tokens = 0_u64;
    for entry in &log.entries {
        let used = entry.tokens_used as u64;
        total_tokens += used;
        if entry.success {
            successful_tokens += used;
        } else {
            failed_tokens += used;
        }
    }

    Some(TokenUsageSummary {
        total_tokens,
        successful_tokens,
        failed_tokens,
        calls: log.entries.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_order_covers_every_dll_category() {
        // Keep CATEGORY_ORDER in sync with the enum's serde variant names.
        const EXPECTED: [&str; 6] = [
            "WindowsOs",
            "MicrosoftSdk",
            "KnownThirdParty",
            "ProjectSpecific",
            "UnknownThirdParty",
            "RuntimeLibrary",
        ];
        let names: Vec<String> = CATEGORY_ORDER
            .iter()
            .map(|category| {
                serde_json::to_value(category)
                    .expect("serialize DllCategory")
                    .as_str()
                    .expect("category serializes to a string")
                    .to_string()
            })
            .collect();
        assert_eq!(names, EXPECTED);
    }

    #[test]
    fn quality_summary_is_none_without_data() {
        let summary = compute_quality_summary(&[]);
        assert_eq!(summary.avg_unit_confidence, None);
        assert_eq!(summary.baseline_pass_rate, None);
        assert_eq!(summary.verification_pass_rate, None);
    }

    #[test]
    fn quality_summary_weights_pass_rates_across_units() {
        fn make_unit(
            confidence: Option<f32>,
            passed: Option<usize>,
            total: Option<usize>,
        ) -> UnitOfWork {
            UnitOfWork {
                id: String::new(),
                name: String::new(),
                kind: calxgloss_types::WorkKind::FunctionTranslation,
                binary: calxgloss_types::BinaryIdentity::default(),
                function: None,
                attempt: 1,
                status: calxgloss_types::ReviewStatus::Queued,
                accepted: false,
                unit_confidence: confidence,
                baseline_tests_passed: passed,
                baseline_tests_total: total,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                context_tier: None,
                dependencies: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                known_gaps: Vec::new(),
                stale: calxgloss_types::dashboard::Staleness::Fresh,
            }
        }
        let summary = compute_quality_summary(&[
            make_unit(Some(0.8), None, None),
            make_unit(Some(0.6), None, None),
            make_unit(None, Some(2), Some(4)),
            make_unit(None, Some(1), Some(4)),
        ]);
        assert!((summary.avg_unit_confidence.unwrap() - 0.7).abs() < 1e-6);
        // 3/8 across units, not the average of 0.5 and 0.25 weighted oddly.
        assert!((summary.baseline_pass_rate.unwrap() - 0.375).abs() < 1e-6);
        assert_eq!(summary.verification_pass_rate, None);
    }
}
