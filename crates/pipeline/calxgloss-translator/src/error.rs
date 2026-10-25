//! Error types for the translation pipeline.

use thiserror::Error;

/// Unified error type for the translation pipeline.
#[derive(Debug, Error)]
pub enum TranslatorError {
    /// Failed to read the function through the analysis seam.
    ///
    /// The source is boxed: `EngineError` carries fat variants, and unboxed
    /// this variant alone pushed `Result`'s `Err` half past clippy's
    /// `result_large_err` threshold.
    #[error("failed to get function '{function}' from DLL '{binary}': {source}")]
    ScanFetch {
        binary: String,
        function: String,
        source: Box<calxgloss_decomp::EngineError>,
    },

    /// Failed to call the LLM.
    #[error("LLM request failed: {0}")]
    Llm(#[from] calxgloss_llm::LlmError),

    /// Failed to build a prompt from the translation request.
    #[error("failed to build prompt: {0}")]
    Prompt(#[from] calxgloss_prompts::PromptError),

    /// Failed to generate or run baseline tests.
    #[error("test generation failed: {0}")]
    TestGen(anyhow::Error),

    /// The LLM returned empty or invalid Rust code.
    #[error("LLM returned empty or invalid code ({} chars)", .code_len)]
    EmptyCode { code_len: usize },

    /// The translation request had insufficient context (no disassembly, no tests).
    #[error("translation request missing required context: {0}")]
    MissingContext(String),

    /// The requested function is a root symbol the pipeline refuses to
    /// translate verbatim — an entry point or an import thunk. The
    /// call-graph batch path already skips or stubs these; an explicitly
    /// named function is refused rather than spending LLM tokens on a body
    /// that owns no logic (a `DelayLoad_` thunk, for instance, decompiles
    /// to an unrecovered jumptable plus a bare `return`). The reason names
    /// the root pattern that matched, or — for a thunk the symbol table
    /// named after its import, invisible to the name patterns — the
    /// self-call body shape that stands in for the pattern (issue #269).
    #[error("refusing to translate '{function}' from '{binary}': {reason}")]
    SkippedRoot {
        binary: String,
        function: String,
        reason: String,
    },

    /// Failed to plan translation order from the call graph.
    #[error("call graph planning failed: {0}")]
    CallGraph(String),

    /// A pass spec carried no LLM at all — neither a prebuilt client nor an
    /// endpoint and model to build one from (issue #323). Assembly refuses
    /// rather than handing back a pipeline that would quietly run without an
    /// LLM; a description that names an endpoint which cannot produce a
    /// client arrives through [`Self::Llm`] instead.
    #[error("cannot assemble a pass without an LLM: {reason}")]
    MissingLlm {
        /// What the spec was missing, in words.
        reason: String,
    },

    /// Assembling a patch-mode pass loaded the engine itself and the load
    /// failed — the binary path was unreadable, or a budget knob the
    /// platform cannot enforce was armed (issue #323).
    #[error("failed to load the Kuna engine for the pass: {0}")]
    EngineLoad(#[from] calxgloss_kuna::KunaError),

    /// A patch pass was assembled without the spec naming a target binary —
    /// the spec's binary path is where a patch pass loads its engine from,
    /// so a description without one cannot run (issue #327).
    #[error("cannot assemble a patch pass without a target binary: {reason}")]
    MissingPatchTarget {
        /// What the spec was missing, in words.
        reason: String,
    },

    /// Assembling the pass's verifier failed (its working directory could
    /// not be created).
    #[error("verifier setup failed: {0}")]
    VerifierSetup(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, TranslatorError>;
