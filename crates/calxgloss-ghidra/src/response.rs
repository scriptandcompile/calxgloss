//! Response types for GhidraMCP API endpoints.
//!
//! These structs map the JSON responses returned by the GhidraMCP server
//! to Rust types that can be passed to the rest of the pipeline.

use calxgloss_types::{DllInfo, Export, FunctionInfo, Import};
use serde::Deserialize;

// ============================================================
// Session responses
// ============================================================

/// Response from `POST /sessions` (create session).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateSessionResponse {
    /// Unique session identifier.
    pub id: String,

    /// The target binary that was loaded into the session.
    pub target: String,

    /// Timestamp when the session was created (ISO 8601 format).
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}

/// Response from `GET /sessions` (list sessions).
#[derive(Debug, Clone, Deserialize)]
pub struct ListSessionsResponse {
    /// List of active sessions.
    pub sessions: Vec<SessionInfo>,
}

/// A single session entry in the list response.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub id: String,

    /// The target binary loaded in this session.
    pub target: String,

    /// Timestamp when the session was created.
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}

// ============================================================
// DLL responses
// ============================================================

/// Response from `GET /sessions/{exe}/dlls` (list DLLs).
#[derive(Debug, Clone, Deserialize)]
pub struct ListDllsResponse {
    /// List of DLL filenames.
    pub dlls: Vec<String>,
}

/// Response from `GET /sessions/{exe}/dlls/{dll}` (DLL info).
#[derive(Debug, Clone, Deserialize)]
pub struct DllInfoResponse {
    /// The DLL analysis data.
    pub dll: DllInfo,
}

/// Response from `GET /sessions/{exe}/dlls/{dll}/imports`.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportsResponse {
    /// List of imported symbols.
    pub imports: Vec<Import>,
}

/// Response from `GET /sessions/{exe}/dlls/{dll}/exports`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExportsResponse {
    /// List of exported symbols.
    pub exports: Vec<Export>,
}

// ============================================================
// Function responses
// ============================================================

/// Response from `GET .../functions/{fn}/disassembly`.
#[derive(Debug, Clone, Deserialize)]
pub struct DisassemblyResponse {
    /// The raw disassembly text.
    pub disassembly: String,

    /// The function address (optional, may be 0 if not set).
    pub address: Option<u64>,
}

/// Response from `GET .../functions/{fn}/decompiler`.
#[derive(Debug, Clone, Deserialize)]
pub struct DecompilerResponse {
    /// The pseudo-C decompiler output.
    pub pseudo_c: String,

    /// The function address.
    pub address: Option<u64>,
}

/// Response from `GET .../functions/{fn}/callgraph`.
#[derive(Debug, Clone, Deserialize)]
pub struct CallgraphResponse {
    /// Neighbor function names in the call graph.
    pub neighbors: Vec<String>,
}

/// Response from `GET .../functions/{fn}` (full function analysis).
#[derive(Debug, Clone, Deserialize)]
pub struct FullFunctionResponse {
    /// Complete function analysis data.
    pub function: FunctionInfo,
}
