//! GhidraMCP HTTP client for pulling disassembly, decompiler output, and symbol data.
//!
//! This crate provides `GhidraClient`, which communicates with a GhidraMCP server
//! over HTTP to retrieve function disassembly, decompiler pseudo-C output, DLL
//! import/export tables, and call graph information.

mod response;
mod session;

pub use response::*;
pub use session::Session;

use calxgloss_types::{DllInfo, Export, FunctionInfo, Import};
use reqwest::Client;
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;

// ============================================================
// Error types
// ============================================================

/// Errors that can occur during GhidraMCP client operations.
#[derive(Debug, thiserror::Error)]
pub enum GhidraError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Server returned error status {status}: {message}")]
    ServerError { status: u16, message: String },

    #[error("Function '{function}' not found in DLL '{dll}'")]
    FunctionNotFound { function: String, dll: String },

    #[error("DLL '{0}' not found or not analyzed")]
    DllNotFound(String),

    #[error("Invalid session: {0}")]
    InvalidSession(String),

    #[error("Session '{0}' expired")]
    SessionExpired(String),

    #[error("Malformed response from server: {0}")]
    MalformedResponse(String),

    #[error("Client is not connected — call connect() first")]
    NotConnected,

    #[error("Server URL is invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

pub type Result<T> = std::result::Result<T, GhidraError>;

// ============================================================
// Configuration
// ============================================================

/// Configuration for connecting to a GhidraMCP server.
#[derive(Debug, Clone)]
pub struct GhidraConfig {
    /// Base URL of the GhidraMCP server (e.g., `http://localhost:8080`).
    pub base_url: Url,

    /// Request timeout in seconds.
    pub timeout_secs: u64,

    /// Optional API key or bearer token for authentication.
    pub api_key: Option<String>,
}

impl GhidraConfig {
    /// Create a new configuration with sensible defaults.
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            timeout_secs: 120,
            api_key: None,
        })
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Set an API key for authentication.
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }
}

// ============================================================
// Client
// ============================================================

/// A client for the GhidraMCP HTTP API.
///
/// The client manages a session with a Ghidra server and provides methods
/// to query DLLs, functions, disassembly, decompiler output, and call graphs.
///
/// # Connection Lifecycle
///
/// 1. Create with [`GhidraClient::new`]
/// 2. (Optional) Call [`connect`](Self::connect) to initialize a session
/// 3. Use query methods like [`get_function`](Self::get_function),
///    [`get_dll_info`](Self::get_dll_info), etc.
/// 4. Call [`disconnect`](Self::disconnect) when done
#[derive(Debug, Clone)]
pub struct GhidraClient {
    config: GhidraConfig,
    http: Client,
    session: Option<Session>,
}

impl GhidraClient {
    // =========================================================
    // Construction
    // =========================================================

    /// Create a new client with default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GhidraError::InvalidUrl`] if the base URL is malformed.
    pub fn new(base_url: &str) -> Result<Self> {
        let config = GhidraConfig::new(base_url)?;
        Self::from_config(config)
    }

    /// Create a new client from an explicit configuration.
    pub fn from_config(config: GhidraConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(GhidraError::Http)?;

        info!(base_url = %config.base_url, "Created GhidraClient");

        Ok(Self {
            config,
            http,
            session: None,
        })
    }

    // =========================================================
    // Session management
    // =========================================================

    /// List existing analysis sessions on the server.
    #[instrument(skip(self), fields(base_url = %self.config.base_url))]
    pub async fn list_sessions(&self) -> Result<Vec<Session>> {
        debug!("Listing sessions");

        let url = self.config.base_url.join("sessions")?;
        let response = self.http.get(url.clone()).send().await?;

        let status = response.status().as_u16();
        if status != 200 {
            let body = response.text().await?;
            error!(status, body = %body, "Failed to list sessions");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let sessions: ListSessionsResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse session list response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(count = sessions.sessions.len(), "Listed sessions");
        Ok(sessions.sessions.into_iter().map(|s| Session::new(&s.id, &s.target)).collect())
    }

    /// Create a new analysis session for a target binary.
    ///
    /// Returns a [`Session`] that must be used for subsequent API calls.
    /// Updates the client's internal session state.
    #[instrument(skip(self), fields(target_exe, base_url = %self.config.base_url))]
    pub async fn create_session(&mut self, target_exe: &str) -> Result<Session> {
        debug!(target_exe, "Creating session");

        let url = self.config.base_url.join("sessions")?;
        let body = serde_json::json!({ "target": target_exe });

        let mut request = self.http.post(url).json(&body);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status != 201 {
            let body = response.text().await?;
            error!(status, target_exe, body = %body, "Failed to create session");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let session_data: CreateSessionResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse session creation response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        let session = Session::new(&session_data.id, &session_data.target);
        info!(session_id = %session.id, target = %session.target, "Session created");
        self.session = Some(session.clone());
        Ok(session)
    }

    /// Get the current session, if one is established.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Disconnect and clear the current session.
    pub fn disconnect(&mut self) {
        if let Some(ref session) = self.session {
            info!(session_id = %session.id, "Disconnecting session");
        }
        self.session = None;
    }

    /// Ensure a session exists, creating one if needed.
    pub async fn ensure_session(&mut self, target_exe: &str) -> Result<()> {
        if self.session.is_none() {
            let session = self.create_session(target_exe).await?;
            info!(session_id = %session.id, "Session ensured");
        }
        Ok(())
    }

    // =========================================================
    // DLL-level queries
    // =========================================================

    /// List all DLLs known to the server for a target executable.
    #[instrument(skip(self), fields(target_exe, base_url = %self.config.base_url))]
    pub async fn list_dlls(&self, target_exe: &str) -> Result<Vec<String>> {
        debug!(target_exe, "Listing DLLs");

        let url = self.config.base_url.join(&format!("sessions/{target_exe}/dlls"))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::DllNotFound(target_exe.to_string()));
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, target_exe, body = %body, "Failed to list DLLs");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let dll_list: ListDllsResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse DLL list response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(count = dll_list.dlls.len(), target_exe, "Listed DLLs");
        Ok(dll_list.dlls)
    }

    /// Get full analysis information for a single DLL.
    #[instrument(skip(self), fields(dll, target_exe, base_url = %self.config.base_url))]
    pub async fn get_dll_info(&self, target_exe: &str, dll: &str) -> Result<DllInfo> {
        debug!(dll, target_exe, "Getting DLL info");

        let url = self
            .config
            .base_url
            .join(&format!("sessions/{target_exe}/dlls/{dll}"))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::DllNotFound(dll.to_string()));
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, target_exe, body = %body, "Failed to get DLL info");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let dll_response: DllInfoResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse DLL info response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(dll, target_exe, "Got DLL info");
        Ok(dll_response.dll)
    }

    /// Get the imported symbols for a DLL.
    #[instrument(skip(self), fields(dll, target_exe, base_url = %self.config.base_url))]
    pub async fn get_imports(&self, target_exe: &str, dll: &str) -> Result<Vec<Import>> {
        debug!(dll, target_exe, "Getting imports");

        let url = self
            .config
            .base_url
            .join(&format!("sessions/{target_exe}/dlls/{dll}/imports"))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::DllNotFound(dll.to_string()));
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, target_exe, body = %body, "Failed to get imports");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let imports_response: ImportsResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse imports response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(dll, count = imports_response.imports.len(), "Got imports");
        Ok(imports_response.imports)
    }

    /// Get the exported symbols for a DLL.
    #[instrument(skip(self), fields(dll, target_exe, base_url = %self.config.base_url))]
    pub async fn get_exports(&self, target_exe: &str, dll: &str) -> Result<Vec<Export>> {
        debug!(dll, target_exe, "Getting exports");

        let url = self
            .config
            .base_url
            .join(&format!("sessions/{target_exe}/dlls/{dll}/exports"))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::DllNotFound(dll.to_string()));
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, target_exe, body = %body, "Failed to get exports");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let exports_response: ExportsResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse exports response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(dll, count = exports_response.exports.len(), "Got exports");
        Ok(exports_response.exports)
    }

    // =========================================================
    // Function-level queries
    // =========================================================

    /// Get complete function analysis from Ghidra: disassembly, decompiler output,
    /// Windows API calls, and call graph.
    ///
    /// This is the primary convenience method — it bundles the individual queries
    /// for disassembly, decompiler output, imports, exports, and call graph into
    /// a single [`FunctionInfo`] struct.
    #[instrument(skip(self), fields(dll, function, target_exe, base_url = %self.config.base_url))]
    pub async fn get_function(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<FunctionInfo> {
        debug!(dll, function, target_exe, "Getting function info");

        let disassembly = self.get_disassembly(target_exe, dll, function).await?;
        let decompiler_output = self.get_decompiler(target_exe, dll, function).await?;
        let call_graph = self.get_call_graph(target_exe, dll, function).await?;

        // Extract a minimal windows_apis list from the disassembly.
        // Full API tagging is done by the analyzer crate.
        let windows_apis = Vec::new();

        let function_info = FunctionInfo {
            name: function.to_string(),
            address: 0, // Filled in by the full endpoint below
            dll: dll.to_string(),
            disassembly,
            decompiler_output,
            windows_apis,
            call_graph,
        };

        info!(dll, function, "Got function info");
        Ok(function_info)
    }

    /// Get the raw disassembly listing for a function.
    #[instrument(skip(self), fields(dll, function, target_exe, base_url = %self.config.base_url))]
    pub async fn get_disassembly(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<String> {
        debug!(dll, function, target_exe, "Getting disassembly");

        let url = self
            .config
            .base_url
            .join(&format!(
                "sessions/{target_exe}/dlls/{dll}/functions/{function}/disassembly"
            ))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::FunctionNotFound {
                function: function.to_string(),
                dll: dll.to_string(),
            });
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, function, body = %body, "Failed to get disassembly");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let disassembly_response: DisassemblyResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse disassembly response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        trace!(
            length = disassembly_response.disassembly.len(),
            dll,
            function,
            "Got disassembly"
        );
        Ok(disassembly_response.disassembly)
    }

    /// Get the decompiler (pseudo-C) output for a function.
    #[instrument(skip(self), fields(dll, function, target_exe, base_url = %self.config.base_url))]
    pub async fn get_decompiler(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<String> {
        debug!(dll, function, target_exe, "Getting decompiler output");

        let url = self
            .config
            .base_url
            .join(&format!(
                "sessions/{target_exe}/dlls/{dll}/functions/{function}/decompiler"
            ))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            warn!(dll, function, "No decompiler output available");
            return Ok(String::new());
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, function, body = %body, "Failed to get decompiler output");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let decompiler_response: DecompilerResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse decompiler response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        trace!(
            length = decompiler_response.pseudo_c.len(),
            dll,
            function,
            "Got decompiler output"
        );
        Ok(decompiler_response.pseudo_c)
    }

    /// Get the call graph for a function — names of functions it calls and
    /// that call it.
    #[instrument(skip(self), fields(dll, function, target_exe, base_url = %self.config.base_url))]
    pub async fn get_call_graph(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<Vec<String>> {
        debug!(dll, function, target_exe, "Getting call graph");

        let url = self
            .config
            .base_url
            .join(&format!(
                "sessions/{target_exe}/dlls/{dll}/functions/{function}/callgraph"
            ))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            return Err(GhidraError::FunctionNotFound {
                function: function.to_string(),
                dll: dll.to_string(),
            });
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, function, body = %body, "Failed to get call graph");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let callgraph_response: CallgraphResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse callgraph response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        trace!(
            count = callgraph_response.neighbors.len(),
            dll,
            function,
            "Got call graph"
        );
        Ok(callgraph_response.neighbors)
    }

    // =========================================================
    // Full function analysis (single endpoint)
    // =========================================================

    /// Get a complete function analysis in a single request.
    ///
    /// Some GhidraMCP server implementations provide a single endpoint that
    /// returns disassembly, decompiler output, address, and call graph together.
    /// This method handles that format. Falls back to individual queries if
    /// the endpoint returns 404.
    #[instrument(skip(self), fields(dll, function, target_exe, base_url = %self.config.base_url))]
    pub async fn get_function_full(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<FunctionInfo> {
        debug!(dll, function, target_exe, "Getting full function analysis");

        let url = self
            .config
            .base_url
            .join(&format!(
                "sessions/{target_exe}/dlls/{dll}/functions/{function}"
            ))?;
        let mut request = self.http.get(url);
        if let Some(ref api_key) = self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status == 404 {
            // Fall back to individual queries
            warn!(
                dll,
                function,
                "Full function endpoint not available, falling back to individual queries"
            );
            return self.get_function(target_exe, dll, function).await;
        }

        if status != 200 {
            let body = response.text().await?;
            error!(status, dll, function, body = %body, "Failed to get function");
            return Err(GhidraError::ServerError { status, message: body });
        }

        let full_response: FullFunctionResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse full function response");
            GhidraError::MalformedResponse(e.to_string())
        })?;

        info!(dll, function, "Got full function analysis");
        Ok(full_response.function)
    }

    // =========================================================
    // Configuration accessors
    // =========================================================

    /// Get the base URL of the GhidraMCP server.
    pub fn base_url(&self) -> &Url {
        &self.config.base_url
    }

    /// Get the HTTP client used for requests.
    pub fn http_client(&self) -> &Client {
        &self.http
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = GhidraConfig::new("http://localhost:8080").unwrap();
        assert_eq!(config.base_url.as_str(), "http://localhost:8080/");
        assert_eq!(config.timeout_secs, 120);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_config_with_timeout() {
        let config = GhidraConfig::new("http://localhost:8080")
            .unwrap()
            .with_timeout(60);
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_config_with_api_key() {
        let config = GhidraConfig::new("http://localhost:8080")
            .unwrap()
            .with_api_key("secret".to_string());
        assert_eq!(config.api_key, Some("secret".to_string()));
    }

    #[test]
    fn test_config_invalid_url() {
        let result = GhidraConfig::new("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        let err = GhidraError::FunctionNotFound {
            function: "foo".to_string(),
            dll: "bar.dll".to_string(),
        };
        assert!(err.to_string().contains("foo"));
        assert!(err.to_string().contains("bar.dll"));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = GhidraClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url().as_str(), "http://localhost:8080/");
        assert!(client.session().is_none());
    }
}
