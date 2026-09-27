//! Local LLM client for sending prompts and receiving Rust code.
//!
//! This crate provides `LlmClient`, which communicates with a local LLM server
//! (Ollama, vLLM, llama.cpp, or any OpenAI-compatible API) over HTTP. It sends
//! prompt messages and receives translated Rust code as the response.

use futures::{Stream, StreamExt};
use reqwest::Client;
use tracing::{debug, error, instrument, trace};

// ============================================================
// Error types
// ============================================================

/// Errors that can occur during LLM client operations.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Server returned a non-success status.
    #[error("server returned error status {status}: {message}")]
    ServerError { status: u16, message: String },

    /// LLM response was empty or could not be parsed.
    #[error("empty or invalid LLM response")]
    EmptyResponse,

    /// Stream chunk could not be parsed.
    #[error("failed to parse stream chunk: {0}")]
    StreamParseError(String),

    /// Response content could not be extracted from the LLM output.
    #[error("no content found in LLM response")]
    NoContent,

    /// The endpoint URL was invalid.
    #[error("invalid endpoint URL: {0}")]
    InvalidUrl(String),
}

pub type Result<T> = std::result::Result<T, LlmError>;

// ============================================================
// Configuration
// ============================================================

/// Configuration for connecting to a local LLM server.
///
/// Supports any OpenAI-compatible API (Ollama, vLLM, llama.cpp, etc.).
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// API endpoint URL (e.g., `http://localhost:8081/v1`).
    pub endpoint: url::Url,

    /// Model name to use (e.g., `qwen3-235b-a22b`).
    pub model: String,

    /// Optional API key for authentication.
    pub api_key: Option<String>,

    /// Maximum number of tokens to generate.
    pub max_tokens: usize,

    /// Sampling temperature (0.0 = deterministic, higher = more creative).
    pub temperature: f32,
}

impl LlmConfig {
    /// Create a new configuration with the given endpoint and model name.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::InvalidUrl`] if the endpoint is not a valid URL.
    pub fn new(endpoint: &str, model: &str) -> Result<Self> {
        Ok(Self {
            endpoint: url::Url::parse(endpoint).map_err(|e| LlmError::InvalidUrl(e.to_string()))?,
            model: model.to_string(),
            api_key: None,
            max_tokens: 8192,
            temperature: 0.1,
        })
    }

    /// Set the API key for authentication.
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Set the maximum number of tokens to generate.
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Set the sampling temperature.
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }
}

// ============================================================
// Message types
// ============================================================

/// The role of a message in a conversation with the LLM.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    /// System-level instructions.
    System,
    /// User input / prompt.
    User,
    /// Assistant (LLM) response.
    Assistant,
}

/// A single message sent to or received from the LLM.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmMessage {
    role: MessageRole,
    content: String,
}

impl LlmMessage {
    /// Create a new system message.
    pub fn system(content: &str) -> Self {
        Self {
            role: MessageRole::System,
            content: content.to_string(),
        }
    }

    /// Create a new user message.
    pub fn user(content: &str) -> Self {
        Self {
            role: MessageRole::User,
            content: content.to_string(),
        }
    }

    /// Create a new assistant message (e.g., for multi-turn conversations).
    pub fn assistant(content: &str) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.to_string(),
        }
    }

    /// Get the role of this message.
    pub fn role(&self) -> &MessageRole {
        &self.role
    }

    /// Get the content of this message.
    pub fn content(&self) -> &str {
        &self.content
    }
}

// ============================================================
// Request / Response types
// ============================================================

/// Internal request body sent to the OpenAI-compatible API.
#[derive(Debug, Clone, serde::Serialize)]
struct LlmRequest {
    model: String,
    messages: Vec<LlmMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<usize>,
}

/// Parsed response from the LLM (non-streaming).
///
/// Matches the OpenAI API response format:
/// ```json
/// {
///   "choices": [{
///     "message": {
///       "role": "assistant",
///       "content": "fn foo() { ... }"
///     }
///   }],
///   "usage": {
///     "completion_tokens": 256
///   }
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize)]
struct LlmResponseRaw {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Message {
    #[serde(rename = "role")]
    _role: String,
    content: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Usage {
    #[serde(rename = "completion_tokens")]
    completion_tokens: Option<usize>,
    #[serde(rename = "total_tokens")]
    total_tokens: Option<usize>,
}

/// Parsed response from the LLM (non-streaming).
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// The generated content (typically Rust code).
    pub content: String,

    /// The model that generated this response.
    pub model: String,

    /// Number of tokens used in the response (if reported by the server).
    pub tokens_used: Option<usize>,
}

// ============================================================
// Streaming types
// ============================================================

/// A single streamed chunk from the LLM.
///
/// Matches the OpenAI streaming format:
/// ```json
/// {
///   "choices": [{
///     "delta": {
///       "role": "assistant",
///       "content": "fn "
///     }
///   }]
/// }
/// ```
#[derive(Debug, serde::Deserialize)]
struct LlmStreamChunk {
    choices: Vec<StreamChoice>,
}

#[derive(Debug, serde::Deserialize)]
struct StreamChoice {
    delta: Option<StreamDelta>,
}

#[derive(Debug, serde::Deserialize)]
struct StreamDelta {
    #[serde(rename = "role")]
    role: Option<String>,
    content: Option<String>,
}

// ============================================================
// Client
// ============================================================

/// A client for local LLM servers with OpenAI-compatible APIs.
///
/// Supports both standard completions and streaming responses.
/// Compatible with Ollama, vLLM, llama.cpp, and other local LLM runners.
#[derive(Debug)]
pub struct LlmClient {
    config: LlmConfig,
    http: Client,
}

impl LlmClient {
    // =========================================================
    // Construction
    // =========================================================

    /// Create a new client with the given configuration.
    pub fn new(config: LlmConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(LlmError::Http)?;

        debug!(
            model = %config.model,
            endpoint = %config.endpoint,
            "Created LlmClient"
        );

        Ok(Self { config, http })
    }

    /// Create a new client from a URL string and model name.
    ///
    /// Uses default values: max_tokens=8192, temperature=0.1.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::InvalidUrl`] if the endpoint is not a valid URL.
    pub fn from_url(endpoint: &str, model: &str) -> Result<Self> {
        let config = LlmConfig::new(endpoint, model)?;
        Self::new(config)
    }

    // =========================================================
    // Completions
    // =========================================================

    /// Send a prompt to the LLM and wait for the full response.
    ///
    /// The response content is post-processed to strip markdown code fences
    /// if present (e.g., ```rust ... ``` blocks).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use calxgloss_llm::{LlmClient, LlmConfig, LlmMessage};
    ///
    /// let client = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let messages = vec![LlmMessage::user("Translate to Rust: x = x + 1")];
    /// let response = client.complete(&messages).await?;
    /// println!("Tokens used: {:?}", response.tokens_used);
    /// # Ok::<_, calxgloss_llm::LlmError>(())
    /// ```
    #[instrument(skip(self, messages), fields(model = %self.config.model, message_count = messages.len()))]
    pub async fn complete(&self, messages: &[LlmMessage]) -> Result<LlmResponse> {
        debug!("Sending completion request");

        let request = LlmRequest {
            model: self.config.model.clone(),
            messages: messages.to_vec(),
            temperature: if self.config.temperature != 0.1 {
                Some(self.config.temperature)
            } else {
                None
            },
            max_tokens: if self.config.max_tokens != 8192 {
                Some(self.config.max_tokens)
            } else {
                None
            },
        };

        let response = self
            .http
            .post(self.completions_url())
            .json(&request)
            .send()
            .await?;

        let status = response.status().as_u16();
        if status != 200 {
            let body = response.text().await?;
            error!(status, body = %body, "LLM request failed");
            return Err(LlmError::ServerError {
                status,
                message: body,
            });
        }

        let raw: LlmResponseRaw = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse LLM response");
            LlmError::EmptyResponse
        })?;

        let choice = raw.choices.first().ok_or(LlmError::NoContent)?;
        let content = choice
            .message
            .content
            .as_ref()
            .ok_or(LlmError::NoContent)?
            .clone();

        let tokens_used = raw
            .usage
            .as_ref()
            .and_then(|u| u.completion_tokens.or(u.total_tokens));

        let cleaned = strip_code_fences(&content);

        trace!(
            length = cleaned.len(),
            tokens = ?tokens_used,
            "Got LLM response"
        );

        Ok(LlmResponse {
            content: cleaned,
            model: self.config.model.clone(),
            tokens_used,
        })
    }

    /// Send a prompt to the LLM and receive a byte stream of the response.
    ///
    /// The returned stream yields one line (NDJSON chunk) at a time from the
    /// server's SSE (Server-Sent Events) stream. Each line can be parsed
    /// with [`serde_json::from_str::<LlmStreamChunk>`].
    ///
    /// The caller is responsible for concatenating the `content` fields from
    /// each chunk to reconstruct the full response.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use calxgloss_llm::{LlmClient, LlmMessage};
    /// use futures::StreamExt;
    ///
    /// let client = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let messages = vec![LlmMessage::user("Translate to Rust")];
    ///
    /// let mut stream = client.complete_streaming(&messages).await?;
    /// let mut full_content = String::new();
    ///
    /// while let Some(chunk) = stream.next().await {
    ///     let json: serde_json::Value = chunk?;
    ///     if let Some(content) = json.get("choices")
    ///         .and_then(|c| c.get(0))
    ///         .and_then(|c| c.get("delta"))
    ///         .and_then(|d| d.get("content"))
    ///         .and_then(|c| c.as_str())
    ///     {
    ///         full_content.push_str(content);
    ///     }
    /// }
    ///
    /// println!("Full response: {}", full_content);
    /// # Ok::<_, calxgloss_llm::LlmError>(())
    /// ```
    #[instrument(skip(self, messages), fields(model = %self.config.model))]
    pub async fn complete_streaming(
        &self,
        messages: &[LlmMessage],
    ) -> Result<impl Stream<Item = Result<serde_json::Value>>> {
        debug!("Sending streaming completion request");

        let request = LlmRequest {
            model: self.config.model.clone(),
            messages: messages.to_vec(),
            temperature: if self.config.temperature != 0.1 {
                Some(self.config.temperature)
            } else {
                None
            },
            max_tokens: if self.config.max_tokens != 8192 {
                Some(self.config.max_tokens)
            } else {
                None
            },
        };

        let response = self
            .http
            .post(self.completions_url())
            .json(&request)
            .header("Accept", "text/event-stream")
            .send()
            .await?;

        let status = response.status().as_u16();
        if status != 200 {
            let body = response.text().await?;
            error!(status, body = %body, "Streaming LLM request failed");
            return Err(LlmError::ServerError {
                status,
                message: body,
            });
        }

        let body = response.bytes_stream();

        Ok(Box::pin(futures::stream::unfold(
            body,
            |mut stream| async {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let text = String::from_utf8_lossy(&chunk).to_string();
                        let parsed = serde_json::from_str::<serde_json::Value>(&text);
                        Some((
                            parsed.map_err(|e| LlmError::StreamParseError(e.to_string())),
                            stream,
                        ))
                    }
                    Some(Err(e)) => Some((Err(LlmError::Http(e)), stream)),
                    None => None,
                }
            },
        )))
    }

    // =========================================================
    // Configuration accessors
    // =========================================================

    /// Get the model name this client is configured to use.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Get the API endpoint URL.
    pub fn endpoint(&self) -> &url::Url {
        &self.config.endpoint
    }

    /// Get the maximum number of tokens configured.
    pub fn max_tokens(&self) -> usize {
        self.config.max_tokens
    }

    /// Get the temperature configured.
    pub fn temperature(&self) -> f32 {
        self.config.temperature
    }

    // =========================================================
    // Internal helpers
    // =========================================================

    fn completions_url(&self) -> String {
        self.config
            .endpoint
            .join("chat/completions")
            .expect("invalid completions URL")
            .to_string()
    }
}

// ============================================================
// Utility functions
// ============================================================

/// Strip markdown code fences from LLM response content.
///
/// LLMs often wrap code in markdown fences (e.g., triple backtick followed by
/// a language tag like `rust`). This function removes the opening and closing
/// fences, returning just the code content.
///
/// If no fences are present, the string is returned unchanged (trimmed).
pub fn strip_code_fences(content: &str) -> String {
    let trimmed = content.trim();

    // Check for fenced code block: ```[language]\n...\n```
    if trimmed.starts_with("```") {
        // Find the first newline to skip the opening fence + optional language tag
        if let Some(newline_pos) = trimmed.find('\n') {
            let after_opening = &trimmed[newline_pos + 1..];

            // Check if it ends with ```
            if after_opening.trim_end().ends_with("```") {
                // Remove the closing ``` and trim whitespace
                let without_closing = after_opening
                    .trim_end()
                    .trim_end_matches('`')
                    .trim_end_matches('\n');
                return without_closing.to_string();
            }

            // No closing fence found — return everything after opening
            return after_opening.trim().to_string();
        }
    }

    trimmed.to_string()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roles() {
        let sys = LlmMessage::system("You are helpful.");
        assert_eq!(sys.role(), &MessageRole::System);
        assert_eq!(sys.content(), "You are helpful.");

        let usr = LlmMessage::user("Hello");
        assert_eq!(usr.role(), &MessageRole::User);

        let ass = LlmMessage::assistant("Hi there");
        assert_eq!(ass.role(), &MessageRole::Assistant);
    }

    #[test]
    fn test_config_defaults() {
        let config = LlmConfig::new("http://localhost:11434/v1", "qwen3").unwrap();
        assert_eq!(config.model, "qwen3");
        assert_eq!(config.max_tokens, 8192);
        assert_eq!(config.temperature, 0.1);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_config_builders() {
        let config = LlmConfig::new("http://localhost:11434/v1", "test")
            .unwrap()
            .with_max_tokens(4096)
            .with_temperature(0.5)
            .with_api_key("key123".to_string());

        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.temperature, 0.5);
        assert_eq!(config.api_key, Some("key123".to_string()));
    }

    #[test]
    fn test_config_invalid_url() {
        let result = LlmConfig::new("not-a-url", "model");
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_code_fences_with_rust() {
        let input = "```rust\nfn foo() { 42 }\n```";
        assert_eq!(strip_code_fences(input), "fn foo() { 42 }");
    }

    #[test]
    fn test_strip_code_fences_with_language() {
        let input = "```\nfn bar() {}\n```";
        assert_eq!(strip_code_fences(input), "fn bar() {}");
    }

    #[test]
    fn test_strip_code_fences_no_fences() {
        let input = "fn bare() { }";
        assert_eq!(strip_code_fences(input), "fn bare() { }");
    }

    #[test]
    fn test_strip_code_fences_with_extra_content() {
        let input = "Here is the code:\n\n```rust\nfn x() {}\n```\n\nHope that helps.";
        // The function only strips if the content starts with ```
        // Since it starts with "Here is the code:\n", no fences are stripped
        assert!(strip_code_fences(input).contains("Here is the code"));
    }

    #[test]
    fn test_strip_code_fences_multiline() {
        let input = "```rust\nfn complex() {\n    let x = 1 + 2;\n    x * 2\n}\n```";
        assert_eq!(
            strip_code_fences(input),
            "fn complex() {\n    let x = 1 + 2;\n    x * 2\n}"
        );
    }

    #[test]
    fn test_message_serialization() {
        let msg = LlmMessage::user("test prompt");
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"test prompt\""));
    }

    #[test]
    fn test_request_serialization() {
        let messages = vec![LlmMessage::user("translate this")];
        let request = LlmRequest {
            model: "qwen3".to_string(),
            messages,
            temperature: None,
            max_tokens: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"model\":\"qwen3\""));
        assert!(!json.contains("\"temperature\"")); // should NOT be present (None with skip_serializing_if)
        assert!(!json.contains("\"max_tokens\"")); // should NOT be present (None with skip_serializing_if)
    }

    #[test]
    fn test_request_serialization_with_optional_fields() {
        let messages = vec![LlmMessage::user("translate this")];
        let request = LlmRequest {
            model: "qwen3".to_string(),
            messages,
            temperature: Some(0.5),
            max_tokens: Some(4096),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"temperature\":0.5"));
        assert!(json.contains("\"max_tokens\":4096"));
    }

    #[test]
    fn test_error_display() {
        let err = LlmError::ServerError {
            status: 500,
            message: "internal error".to_string(),
        };
        assert!(err.to_string().contains("500"));
        assert!(err.to_string().contains("internal error"));

        let err = LlmError::EmptyResponse;
        assert!(err.to_string().contains("empty"));
    }
}
