//! Context-window detector for the LLM client.
//!
//! This module provides [`ContextWindowDetector`] which inspects LLM responses
//! and requests to detect when the model's context window is being exceeded.
//! It is the primary mechanism for fault detection.
//!
//! # How it works
//!
//! After each LLM call the detector checks:
//!
//! 1. **Response size vs. configured limit** — if the response text (in
//!    characters) meets or exceeds `max_tokens × 4` (rough estimate of
//!    characters-per-token), a [`ContextWindowFault`](calxgloss_types::ContextWindowFault)
//!    is raised.
//! 2. **Truncation signals** — the response body is scanned for markers that
//!    some LLM runners append when they cut output short (e.g. `"[response
//!    truncated]"` or `"[output limited]"`).
//! 3. **Prompt size estimation** — the total prompt size (system + user
//!    messages, in characters) is compared to the model's input context limit.
//!    If the prompt itself is too large the LLM may silently drop earlier
//!    messages or produce degraded output.
//!
//! When a fault is detected the caller should split the function into smaller
//! chunks and retry with focused context.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_llm::{LlmClient, LlmConfig, LlmMessage};
//! use calxgloss_llm::context::ContextWindowDetector;
//! use calxgloss_types::ContextWindowFault;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let detector = ContextWindowDetector::new(client.max_tokens());
//!
//! let messages = vec![LlmMessage::user("Translate this function...")];
//! let response = client.complete(&messages).await?;
//!
//! if let Some(fault) = detector.detect_response(&response, 50) {
//!     eprintln!("Context window fault: {}", fault.overflow_chars);
//!     // Split the function and retry...
//! }
//! # Ok(())
//! # }
//! ```

use crate::LlmResponse;
use calxgloss_types::ContextWindowFault;

/// Default characters-per-token ratio used when converting token counts to
/// character estimates.  LLM tokenizers produce ~4 characters per token on
/// average for English source code, which is a safe approximation.
const DEFAULT_CHARS_PER_TOKEN: usize = 4;

/// Default input context limit in tokens.  When the model-specific limit is
/// not known this value is used as a conservative estimate.
const DEFAULT_INPUT_LIMIT_TOKENS: usize = 131_072;

/// Detects context-window exceeded faults from LLM requests and responses.
///
/// The detector is created with the model's configured output limit
/// (`max_tokens`) and uses a standard characters-per-token ratio to convert
/// token counts to character thresholds.
#[derive(Debug, Clone)]
pub struct ContextWindowDetector {
    /// Maximum output tokens the model is configured to generate.
    max_output_tokens: usize,

    /// Estimated input context limit in tokens.
    input_limit_tokens: usize,

    /// Estimated characters per token ratio.
    chars_per_token: usize,
}

impl ContextWindowDetector {
    /// Create a new detector with the given output limit.
    ///
    /// # Arguments
    ///
    /// * `max_output_tokens` — The `max_tokens` setting passed to the LLM
    ///   client. When the response exceeds this, a fault is raised.
    pub fn new(max_output_tokens: usize) -> Self {
        Self {
            max_output_tokens,
            input_limit_tokens: DEFAULT_INPUT_LIMIT_TOKENS,
            chars_per_token: DEFAULT_CHARS_PER_TOKEN,
        }
    }

    /// Create a new detector with all limits explicitly configured.
    pub fn with_limits(
        max_output_tokens: usize,
        input_limit_tokens: usize,
        chars_per_token: usize,
    ) -> Self {
        Self {
            max_output_tokens,
            input_limit_tokens,
            chars_per_token,
        }
    }

    /// Compute the character threshold for the output limit.
    pub fn output_limit_chars(&self) -> usize {
        self.max_output_tokens * self.chars_per_token
    }

    /// Compute the character threshold for the input limit.
    pub fn input_limit_chars(&self) -> usize {
        self.input_limit_tokens * self.chars_per_token
    }

    /// Inspect an LLM response and return a fault if the response is at or
    /// beyond the configured output limit.
    ///
    /// This is the primary detection method called after every
    /// [`LlmClient::complete`](calxgloss_llm::LlmClient::complete) call.
    ///
    /// # Arguments
    ///
    /// * `response` — The response received from the LLM.
    /// * `disassembly_lines` — The number of lines in the original function's
    ///   disassembly. Used to compute a suggested chunk count for the retry
    ///   splitter.
    ///
    /// # Returns
    ///
    /// [`Some`]`(`[`ContextWindowFault`]`)` if a context-window fault is
    /// detected, [`None`] otherwise.
    pub fn detect_response(
        &self,
        response: &LlmResponse,
        disassembly_lines: usize,
    ) -> Option<ContextWindowFault> {
        let response_size = response.content.len();
        let limit = self.output_limit_chars();

        // Check for explicit truncation markers in the response body.
        // Many LLM runners append these when output hits the token ceiling.
        let has_truncation_signal = is_truncated_response(&response.content);

        if has_truncation_signal {
            return Some(ContextWindowFault::truncated(
                response_size,
                limit,
                disassembly_lines,
            ));
        }

        if response_size >= limit {
            return Some(ContextWindowFault::response_exceeds_limit(
                response_size,
                limit,
                disassembly_lines,
            ));
        }

        None
    }

    /// Estimate the total size of a set of messages in characters.
    ///
    /// Used to determine whether the **input** prompt itself exceeds the
    /// model's context window before sending it.
    pub fn estimate_prompt_size(messages: &[crate::LlmMessage]) -> usize {
        messages.iter().map(|m| m.content().len()).sum()
    }

    /// Inspect a prompt and return a fault if the estimated input size
    /// exceeds the model's context window.
    ///
    /// # Arguments
    ///
    /// * `messages` — The messages that will be sent to the LLM.
    ///
    /// # Returns
    ///
    /// [`Some`]`(`[`ContextWindowFault`]`)` if the prompt is too large,
    /// [`None`] otherwise.
    pub fn detect_prompt_too_large(
        &self,
        messages: &[crate::LlmMessage],
    ) -> Option<ContextWindowFault> {
        let prompt_size = Self::estimate_prompt_size(messages);
        let limit = self.input_limit_chars();

        if prompt_size >= limit {
            return Some(ContextWindowFault::response_exceeds_limit(
                prompt_size,
                limit,
                0, // disassembly lines unknown at this stage
            ));
        }

        None
    }
}

// ============================================================
// Truncation signal detection
// ============================================================

/// Check whether an LLM response body contains explicit truncation markers.
///
/// Different LLM runners use different signals. This function checks for the
/// most common ones used by Ollama, vLLM, llama.cpp, and other local servers.
///
/// Common markers:
/// - `"[response truncated]"` — generic
/// - `"[output limited]"` — vLLM
/// - `"[maximum tokens reached]"` — Ollama
/// - `"[generation cutoff]"` — llama.cpp
/// - `"<|endoftext|>"` — GPT-style EOS token leakage
///
/// The check is case-insensitive.
fn is_truncated_response(content: &str) -> bool {
    let lower = content.to_lowercase();
    [
        "[response truncated]",
        "[output limited]",
        "[maximum tokens reached]",
        "[generation cutoff]",
        "generation was cut off",
        "output was truncated",
        "[end of response]",
        "<|endoftext|>",
    ]
    .into_iter()
    .any(|marker| lower.contains(marker))
}

// ============================================================
// Function splitter — splits disassembly into basic-block chunks
// ============================================================

/// Splits a function's disassembly into smaller chunks suitable for
/// context-window-limited LLM calls.
///
/// The splitter works by identifying function boundaries in the disassembly
/// (instruction addresses, labels, control-flow markers) and dividing the
/// text into roughly equal-sized blocks. Each chunk is accompanied by
/// metadata that tells the LLM to focus only on that region.
#[derive(Debug, Clone)]
pub struct FunctionSplitter;

impl FunctionSplitter {
    /// Split disassembly text into `chunk_count` chunks.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL name (used in chunk metadata).
    /// * `function` — The function name (used in chunk metadata).
    /// * `disassembly` — The full disassembly text.
    /// * `decompiler_output` — The decompiler/pseudo-C output (may be empty).
    /// * `chunk_count` — Number of chunks to produce (at least 2).
    ///
    /// # Returns
    ///
    /// A vector of [`FunctionChunk`] instances, each containing a slice of the
    /// disassembly and decompiler output with metadata for the LLM.
    pub fn split(
        dll: &str,
        function: &str,
        disassembly: &str,
        decompiler_output: &str,
        chunk_count: usize,
    ) -> Vec<FunctionChunk> {
        let chunk_count = chunk_count.max(2);
        let lines: Vec<&str> = disassembly.lines().collect();
        let total = lines.len();
        if total == 0 {
            return vec![FunctionChunk {
                dll: dll.to_string(),
                function: function.to_string(),
                chunk_index: 0,
                chunk_total: 1,
                disassembly: String::new(),
                decompiler_context: decompiler_output.to_string(),
            }];
        }

        let lines_per_chunk = (total as f64 / chunk_count as f64).ceil() as usize;
        let mut chunks = Vec::with_capacity(chunk_count);

        for i in 0..chunk_count {
            let start = i * lines_per_chunk;
            let end = std::cmp::min((i + 1) * lines_per_chunk, total);

            if start >= total {
                break;
            }

            let chunk_lines: Vec<&str> = lines[start..end].to_vec();
            let disassembly_chunk = chunk_lines.join("\n");

            chunks.push(FunctionChunk {
                dll: dll.to_string(),
                function: function.to_string(),
                chunk_index: i,
                chunk_total: chunk_count,
                disassembly: disassembly_chunk,
                decompiler_context: decompiler_output.to_string(),
            });
        }

        // Safety: ensure we have at least one chunk even if the math above
        // produced none (e.g., chunk_count > total lines).
        if chunks.is_empty() {
            chunks.push(FunctionChunk {
                dll: dll.to_string(),
                function: function.to_string(),
                chunk_index: 0,
                chunk_total: 1,
                disassembly: disassembly.to_string(),
                decompiler_context: decompiler_output.to_string(),
            });
        }

        chunks
    }
}

/// A single chunk produced by [`FunctionSplitter`].
///
/// Contains a slice of the original disassembly plus enough decompiler
/// context for the LLM to understand the surrounding code structure.
#[derive(Debug, Clone)]
pub struct FunctionChunk {
    /// The DLL name.
    pub dll: String,

    /// The function name.
    pub function: String,

    /// Zero-based index of this chunk (0..chunk_total).
    pub chunk_index: usize,

    /// Total number of chunks this function was split into.
    pub chunk_total: usize,

    /// The disassembly lines for this chunk only.
    pub disassembly: String,

    /// The full decompiler output (kept in every chunk so the LLM has context
    /// about the function signature and surrounding blocks).
    pub decompiler_context: String,
}

impl FunctionChunk {
    /// Build a prompt-ready context string for this chunk.
    ///
    /// Includes a header indicating which chunk this is, so the LLM knows
    /// to focus only on the provided disassembly lines.
    pub fn prompt_context(&self) -> String {
        format!(
            "FUNCTION CHUNK {}/{}\n\
             DLL: {}\n\
             FUNCTION: {}\n\
             ---\n\
             {}\n\
             ---\n\
             DECOMPILER CONTEXT:\n\
             {}\n\
             ---\n\
             Translate ONLY the disassembly above. Focus on chunk {}/{}.",
            self.chunk_index + 1,
            self.chunk_total,
            self.dll,
            self.function,
            self.decompiler_context.trim(),
            self.disassembly.trim(),
            self.chunk_index + 1,
            self.chunk_total,
        )
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_output_limit_chars() {
        let detector = ContextWindowDetector::new(8192);
        assert_eq!(detector.output_limit_chars(), 8192 * 4); // 32768
    }

    #[test]
    fn test_detector_input_limit_chars() {
        let detector = ContextWindowDetector::new(8192);
        assert_eq!(
            detector.input_limit_chars(),
            DEFAULT_INPUT_LIMIT_TOKENS * DEFAULT_CHARS_PER_TOKEN
        );
    }

    #[test]
    fn test_detect_response_no_fault_normal_size() {
        let detector = ContextWindowDetector::new(8192);
        let response = LlmResponse {
            content: "fn foo() { 42 }".to_string(),
            model: "qwen3".to_string(),
            tokens_used: Some(100),
        };
        let fault = detector.detect_response(&response, 50);
        assert!(fault.is_none());
    }

    #[test]
    fn test_detect_response_no_fault_near_limit() {
        let detector = ContextWindowDetector::new(100); // 100 tokens → 400 chars
        let response = LlmResponse {
            content: "x".repeat(300), // under limit
            model: "qwen3".to_string(),
            tokens_used: None,
        };
        let fault = detector.detect_response(&response, 50);
        assert!(fault.is_none());
    }

    #[test]
    fn test_detect_response_fault_at_limit() {
        let detector = ContextWindowDetector::new(100); // 400 chars
        let response = LlmResponse {
            content: "x".repeat(400), // exactly at limit
            model: "qwen3".to_string(),
            tokens_used: None,
        };
        let fault = detector.detect_response(&response, 50).unwrap();
        assert!(fault.is_over_limit());
    }

    #[test]
    fn test_detect_response_fault_over_limit() {
        let detector = ContextWindowDetector::new(100); // 400 chars
        let response = LlmResponse {
            content: "x".repeat(500), // over limit
            model: "qwen3".to_string(),
            tokens_used: None,
        };
        let fault = detector.detect_response(&response, 50).unwrap();
        assert!(fault.is_over_limit());
        assert_eq!(fault.overflow_chars, 100);
    }

    #[test]
    fn test_detect_response_truncation_signal() {
        let detector = ContextWindowDetector::new(8192);
        let response = LlmResponse {
            content: "fn foo() { ... }\n[response truncated]".to_string(),
            model: "qwen3".to_string(),
            tokens_used: None,
        };
        let fault = detector.detect_response(&response, 100).unwrap();
        assert!(fault.has_truncation_signal);
    }

    #[test]
    fn test_prompt_size_estimation() {
        let m1 = crate::LlmMessage::user("Hello world");
        let m2 = crate::LlmMessage::system("You are a translator.");
        let size = ContextWindowDetector::estimate_prompt_size(&[m1, m2]);
        assert_eq!(size, "Hello world".len() + "You are a translator.".len());
    }

    #[test]
    fn test_detect_prompt_too_large() {
        let detector = ContextWindowDetector::with_limits(8192, 1000, 1); // 1000 char input limit
        let messages = vec![crate::LlmMessage::user(&"x".repeat(1100))];
        let fault = detector.detect_prompt_too_large(&messages).unwrap();
        assert!(fault.is_over_limit());
    }

    #[test]
    fn test_detect_prompt_within_limit() {
        let detector = ContextWindowDetector::with_limits(8192, 1000, 1); // 1000 char input limit
        let messages = vec![crate::LlmMessage::user(&"x".repeat(500))];
        let fault = detector.detect_prompt_too_large(&messages);
        assert!(fault.is_none());
    }

    #[test]
    fn test_is_truncated_response_various_markers() {
        assert!(is_truncated_response("fn foo() {}\n[response truncated]"));
        assert!(is_truncated_response("[OUTPUT LIMITED] fn foo() {}"));
        assert!(is_truncated_response("[maximum tokens reached]"));
        assert!(is_truncated_response("[generation cutoff]"));
        assert!(is_truncated_response("output was truncated early"));
        assert!(is_truncated_response("generation was cut off"));

        // Normal responses should not trigger
        assert!(!is_truncated_response("fn foo() { return 42; }"));
        assert!(!is_truncated_response("fn bar() { /* comment */ }"));
    }

    #[test]
    fn test_function_splitter_basic() {
        let disassembly = (0..100)
            .map(|i| format!("0x{:08x}:  mov eax, {}\n", 0x1000 + i * 4, i))
            .collect::<String>();

        let chunks = FunctionSplitter::split(
            "test.dll",
            "entry",
            &disassembly,
            "int entry() { return 0; }",
            5,
        );

        assert_eq!(chunks.len(), 5);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.dll, "test.dll");
            assert_eq!(chunk.function, "entry");
            assert_eq!(chunk.chunk_index, i);
            assert_eq!(chunk.chunk_total, 5);
            assert!(!chunk.disassembly.is_empty());
        }
    }

    #[test]
    fn test_function_splitter_minimum_chunks() {
        let chunks = FunctionSplitter::split("d.dll", "f", "line1\nline2", "", 1);
        // chunk_count is clamped to at least 2
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn test_function_splitter_empty_disassembly() {
        let chunks = FunctionSplitter::split("d.dll", "f", "", "int f() { return 0; }", 3);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].disassembly.is_empty());
    }

    #[test]
    fn test_function_chunk_prompt_context() {
        let mut chunks = FunctionSplitter::split(
            "test.dll",
            "entry",
            "0x1000: mov eax, 1\n0x1004: ret",
            "int entry() { return 1; }",
            2,
        );
        let ctx = chunks.remove(0).prompt_context();
        assert!(ctx.contains("FUNCTION CHUNK 1/2"));
        assert!(ctx.contains("test.dll"));
        assert!(ctx.contains("entry"));
        assert!(ctx.contains("0x1000"));
    }

    #[test]
    fn test_detector_custom_chars_per_token() {
        let detector = ContextWindowDetector::with_limits(4096, 65536, 5);
        assert_eq!(detector.output_limit_chars(), 4096 * 5);
        assert_eq!(detector.input_limit_chars(), 65536 * 5);
    }
}
