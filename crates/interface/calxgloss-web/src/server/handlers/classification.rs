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
//! The record-and-override pair comes from the review-surface reader
//! (issue #461) — the panel never joins record paths or guesses the
//! document's shape itself. The binary in the path is the binary identity
//! — the filename verbatim, the same key the override records are stored
//! under.

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

/// The response both endpoints echo: the binary addressed, what the
/// workspace recorded for it, and the override now in force — both read
/// through the review-surface reader (issue #461). A corrupt record still
/// lists the binary, its category honestly `unknown` and its reason
/// naming the fault that stopped the read; a corrupt override document is
/// a server fault naming the document, never a silent "no override".
fn classification_response(
    combined: &CombinedState,
    binary: &str,
) -> Result<Json<BinaryClassificationResponse>, ServerError> {
    let pair = combined.reader.classification_pair(binary)?;
    Ok(Json(BinaryClassificationResponse {
        binary: binary.to_string(),
        classification: pair.recorded,
        r#override: pair.r#override,
    }))
}

/// Handle `GET /api/binaries/{name}/classification` — the current
/// classification with its reasoning, and the override in force for this
/// binary (`null` when none is set). Live router only.
pub async fn api_get_binary_classification(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
) -> Result<Json<BinaryClassificationResponse>, ServerError> {
    classification_handle(&combined)?;
    classification_response(&combined, &binary)
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
    classification_response(&combined, &binary)
}
