//! Local LLM client for sending prompts and receiving Rust code.
//!
//! `LlmClient` talks over HTTP to a locally hosted model — Ollama, vLLM,
//! llama.cpp, or any OpenAI-compatible API. It sends the prompt messages and
//! returns the translated Rust code the model produced.
//!
//! # Modules
//!
//! - [`context`] — Context-window detection and function splitting for
//!   fault recovery.
//! - [`hallucination`] — Detection of hallucinated function calls.
//! - [`infinite_loop`] — Detection of a retry loop stuck repeating the same
//!   output.
//! - [`behavior_divergence`] — Detection of behavior divergence from expected output.
//! - [`resource_exhaustion`] — Detection of resource-exhaustion signals.

pub mod behavior_divergence;
mod client;
pub mod context;
pub mod hallucination;
pub mod infinite_loop;
pub mod resource_exhaustion;

pub use behavior_divergence::{BehaviorDivergenceDetector, EdgeCaseTest};
pub use client::{
    LlmClient, LlmConfig, LlmError, LlmMessage, LlmResponse, MessageRole, Result, strip_code_fences,
};
pub use context::{ContextWindowDetector, FunctionChunk, FunctionSplitter};
pub use hallucination::{HallucinatedCall, HallucinationDetector};
pub use infinite_loop::InfiniteLoopDetector;
pub use resource_exhaustion::{ExhaustionSignal, ResourceExhaustionDetector};
