//! Binary classification override endpoints (issue #97, W2.8).
//!
//! An operator corrects a misclassified target binary from the dashboard
//! instead of a CLI re-run. GET reports the current classification with its
//! reasoning alongside the override in force; POST applies (or, with
//! `override: null`, removes) the override record. Both are live-router
//! only — a plain `serve` router has no run to steer — and each answers
//! 503 when the live router was built without a classification-override
//! handle attached, mirroring the scope and unit-override honesty rules.
//!
//! The binary in the path is the binary identity — the filename verbatim,
//! the same key the override records are stored under.

use std::path::Path;

use super::super::{
    BinaryClassificationRequest, BinaryClassificationResponse, CombinedState, ServerError,
};

use axum::{
    Json,
    extract::{Path as PathExtractor, State},
};
use calxgloss_types::ClassificationOverrideControl;
use tracing::info;

/// The classification-override handle both endpoints need: 503 when this
/// live router was built without one — honest rather than steering a
/// classification pipeline that does not exist.
fn classification_handle(
    combined: &CombinedState,
) -> Result<ClassificationOverrideControl, ServerError> {
    combined
        .server
        .classification_override_control()
        .ok_or_else(|| {
            ServerError::unavailable("this server has no classification override control attached")
        })
}

/// The classification artifact path for one binary — the same sanitization
/// the classify command uses when it writes the file (`/` and `\` become `_`).
pub(crate) fn classification_record_path(repo_path: &Path, binary: &str) -> std::path::PathBuf {
    let sanitized: String = binary
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    repo_path
        .join("re")
        .join("classify")
        .join(format!("{sanitized}.json"))
}

/// The classification the run recorded for this binary, read from its
/// `re/classify/{binary}.json` artifact. A missing, corrupt, or
/// name/category-less record is no record at all — the response says so
/// rather than guessing.
fn recorded_classification(
    repo_path: &Path,
    binary: &str,
) -> Option<super::super::types::RecordedClassification> {
    let content = std::fs::read_to_string(classification_record_path(repo_path, binary)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let category = value.get("category").and_then(|v| v.as_str())?;
    if category.is_empty() {
        return None;
    }
    // Strategy is serialized from `calxgloss_analysis::Strategy`: unit
    // variants become bare strings ("PalMapping"), struct variants become
    // tagged objects ({"CrateReplacement": {…}}). Either way, the variant
    // name is the strategy — the same reading the pipeline rows use.
    let strategy = match value.get("strategy") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Object(obj)) => obj.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    };
    Some(super::super::types::RecordedClassification {
        category: category.to_string(),
        strategy,
        crate_replacement: value
            .get("crate_replacement")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        known_runtime: value
            .get("known_runtime")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        reason: value
            .get("reason")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// The response both endpoints echo: the binary addressed, what the
/// workspace recorded for it, and the override now in force.
fn classification_response(
    combined: &CombinedState,
    overrides: &ClassificationOverrideControl,
    binary: &str,
) -> Json<BinaryClassificationResponse> {
    Json(BinaryClassificationResponse {
        binary: binary.to_string(),
        classification: recorded_classification(combined.server.repo_path(), binary),
        r#override: overrides.get(binary),
    })
}

/// Handle `GET /api/binaries/{name}/classification` — the current
/// classification with its reasoning, and the override in force for this
/// binary (`null` when none is set). Live router only.
pub async fn api_get_binary_classification(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
) -> Result<Json<BinaryClassificationResponse>, ServerError> {
    let overrides = classification_handle(&combined)?;
    Ok(classification_response(&combined, &overrides, &binary))
}

/// Handle `POST /api/binaries/{name}/classification` — apply (replace) the
/// operator's override record for this binary; `override: null` removes it
/// and the binary falls back to its recorded classification. The analyzer
/// honors the category and the `known_runtime` flag before classification-
/// strategy dispatch, and the record persists under the workspace so a
/// restarted run honors it too. Live router only.
pub async fn api_set_binary_classification(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
    Json(request): Json<BinaryClassificationRequest>,
) -> Result<Json<BinaryClassificationResponse>, ServerError> {
    let overrides = classification_handle(&combined)?;
    match request.r#override {
        Some(record) => {
            let category = serde_json::to_value(&record.category)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string());
            overrides.set(&binary, record).map_err(|e| {
                ServerError::internal(&format!("failed to persist classification override: {e}"))
            })?;
            info!(
                binary,
                category, "override: binary classification overridden via API"
            );
        }
        None => {
            overrides.remove(&binary).map_err(|e| {
                ServerError::internal(&format!("failed to persist classification override: {e}"))
            })?;
            info!(
                binary,
                "override: binary classification override removed via API"
            );
        }
    }
    Ok(classification_response(&combined, &overrides, &binary))
}
