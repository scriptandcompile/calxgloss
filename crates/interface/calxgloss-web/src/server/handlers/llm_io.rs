//! `GET /api/llm-io` — the server-side LLM I/O log read endpoint (issue #77).
//!
//! Registered in the shared routes: it reads the persisted log at
//! `re/analysis/llm_io/log.jsonl`, never live pipeline state, so every
//! router answers it. A workspace whose live run never emitted LLM traffic
//! (or never ran live at all) honestly gets an empty payload.

use super::super::{LlmIoLog, LlmIoLogResponse, ServerState};
use axum::{Json, extract::State};

/// Serves the retained LLM I/O entries with their metadata and token counts.
pub async fn api_get_llm_io_log(State(state): State<ServerState>) -> Json<LlmIoLogResponse> {
    let log = LlmIoLog::new(state.repo_path());
    Json(LlmIoLogResponse {
        entries: log.read(),
    })
}
