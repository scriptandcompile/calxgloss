//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`context`] — Data structs (`SignaturePromptData`, `ComplexityPromptData`, etc.)
//! - [`templates`] — Askama template structs (`MinimalTemplate`, `TranslateTemplate`, etc.)
//! - [`build_translate_prompt`] — Builds a standard translation prompt
//! - [`build_complexity_prompt`] — Selects template by complexity
//! - [`build_signature_prompt`] — Builds a Tier 0 (name-and-signature-only) prompt
//! - [`build_disassembly_prompt`] — Builds a Tier 1 (disassembly + decompiler) prompt
//! - [`build_with_tests_prompt`] — Builds a Tier 2 (disassembly + decompiler + tests) prompt
//! - [`ComplexityPromptData::api_categories`] — Extracts API categories
//!
//! # Call Graph Context (Task 11)
//!
//! Starting with Tier 2+, prompts can include enriched call graph context
//! produced by [`calxgloss_callgraph::ContextEnricher`]. The context includes:
//!
//! - **Callers** — functions that call this function, with call type
//! - **Categorized callees** — APIs grouped by category (UI, Graphics, etc.)
//! - **Leaf API suggestions** — matched APIs with Rust crate recommendations
//!
//! Use the `from_request_with_call_graph` constructor on prompt data structs
//! to automatically enrich the context from a call graph.
//!
//! # API-Aware Prompt Augmentation
//!
//! When a function calls Windows APIs, the prompt builder automatically
//! adds the full mapping table rows for each API category those calls belong to.
//! This gives the LLM detailed context about how to translate specific APIs
//! (e.g., every Win32 Core mapping, every DirectX mapping, every GDI mapping)
//! rather than just the one-liner `api.name → api.pal_mapping` shown in the
//! "WINDOWS APIS IDENTIFIED" section.

mod build;
pub mod context;
pub mod error;
pub mod templates;

pub use build::{
    build_complexity_prompt, build_disassembly_prompt, build_edge_case_prompt,
    build_escalate_prompt, build_escalate_prompt_with_context, build_full_module_prompt,
    build_module_context_prompt, build_signature_prompt, build_translate_prompt,
    build_with_tests_prompt, extract_signature_from_decompiler,
};
pub use context::{
    ComplexityPromptData, DisassemblyPromptData, SignaturePromptData, WithTestsPromptData,
};
pub use error::PromptError;
pub use templates::capability_for;
pub use templates::{
    AlgorithmInfo, ApiInfo, BoundaryValue, CallGraphNeighbor, CallbackInfo, CapabilityInfo,
    ConcurrencyInfo, ConstInfo, ControlFlowInfo, ConventionInfo, CoverageInfo, DataTableInfo,
    EdgeCaseTemplate, EdgeCaseTest, ErrhandlingInfo, EscalateTemplate, EvidenceBundle, FixTemplate,
    FloatsimdInfo, FormattedTestResult, FullModuleTemplate, GlobalStateInfo, LibmatchInfo,
    MemoryInfo, MinimalTemplate, ModuleContextTemplate, NeighborFunction, PalTraitDef,
    PalTraitMethod, ParameterDirectionInfo, SerializationInfo, ShimCode, SignatureTemplate,
    StringContextInfo, StructField, StructuredData, TestCaseFormatted, TranslateTemplate, TypeInfo,
    UnknownInfo, WithTestsTemplate,
};

// Re-export types used by template constructors
pub use calxgloss_types::{ApiCategory, FunctionComplexity, TranslationRequest};

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
