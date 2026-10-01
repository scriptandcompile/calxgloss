//! Local LLM client for sending prompts and receiving Rust code.
//!
//! This crate provides `LlmClient`, which communicates with a local LLM server
//! (Ollama, vLLM, llama.cpp, or any OpenAI-compatible API) over HTTP. It sends
//! prompt messages and receives translated Rust code as the response.
//!
//! # Modules
//!
//! - [`context`] — Context-window detection and function splitting for
//!   fault recovery.
//! - [`hallucination`] — Detection of hallucinated function calls.
//! - [`infinite_loop`] — Detection of retry-loop divergence.
//! - [`behavior_divergence`] — Detection of behavior divergence from expected output.
//! - [`resource_exhaustion`] — Detection of resource-exhaustion signals.

mod client;
pub mod behavior_divergence;
pub mod context;
pub mod hallucination;
pub mod infinite_loop;
pub mod resource_exhaustion;

pub use client::{
    LlmClient, LlmConfig, LlmError, LlmMessage, LlmResponse, MessageRole, Result,
    strip_code_fences,
};
pub use behavior_divergence::{BehaviorDivergenceDetector, EdgeCaseTest};
pub use context::{ContextWindowDetector, FunctionChunk, FunctionSplitter};
pub use hallucination::{HallucinatedCall, HallucinationDetector};
pub use infinite_loop::InfiniteLoopDetector;
pub use resource_exhaustion::{ExhaustionSignal, ResourceExhaustionDetector};
