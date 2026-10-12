//! `GET /api/llm-io` — the server-side LLM I/O log read endpoint (issue #77),
//! and `POST /api/llm-io/clear` — the delete behind the web view's Clear
//! button, so clearing survives a reload instead of resurrecting from disk.
//!
//! Registered in the shared routes: it reads the persisted log at
//! `re/analysis/llm_io/log.jsonl`, never live pipeline state, so every
//! router answers it. A workspace whose live run never emitted LLM traffic
//! (or never ran live at all) honestly gets an empty payload.

use super::super::{LlmIoClearResponse, LlmIoLog, LlmIoLogResponse, ServerError, ServerState};
use axum::{Json, extract::State};

/// Serves the retained LLM I/O entries with their metadata and token counts.
pub async fn api_get_llm_io_log(State(state): State<ServerState>) -> Json<LlmIoLogResponse> {
    let log = LlmIoLog::new(state.repo_path());
    Json(LlmIoLogResponse {
        entries: log.read(),
    })
}

/// Empties the persisted LLM I/O log so the next read (a page reload) starts
/// from an empty history. Idempotent; a failed delete answers 500 rather
/// than pretending the history is gone while a reload would bring it back.
pub async fn api_clear_llm_io_log(
    State(state): State<ServerState>,
) -> Result<Json<LlmIoClearResponse>, ServerError> {
    let log = LlmIoLog::new(state.repo_path());
    let dropped = log
        .clear()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    Ok(Json(LlmIoClearResponse { dropped }))
}
