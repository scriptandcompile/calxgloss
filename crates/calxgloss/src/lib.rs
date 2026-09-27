//! Calxgloss — unified library re-exporting all workspace crates.
//!
//! This crate re-exports all public types, structs, enums, and functions
//! from the Calxgloss workspace crates for convenient single-crate access.
//!
//! # Usage
//!
//! ```
//! use calxgloss::{GhidraClient, LlmClient, TranslationPipeline, ApiMappings};
//! ```

// ============================================================
// calxgloss-types — shared data structures
// ============================================================

pub use calxgloss_types::dll::*;
pub use calxgloss_types::error::TypesError;
pub use calxgloss_types::function::*;
pub use calxgloss_types::git::*;
pub use calxgloss_types::test::*;
pub use calxgloss_types::translation::{WindowsApiCall};
pub use calxgloss_types::verification::{FailedTest, VerificationResult};

// ============================================================
// calxgloss-ghidra — GhidraMCP HTTP client
// ============================================================

pub use calxgloss_ghidra::DisassemblyResponse;
pub use calxgloss_ghidra::ExportsResponse;
pub use calxgloss_ghidra::FullFunctionResponse;
pub use calxgloss_ghidra::GhidraClient;
pub use calxgloss_ghidra::GhidraConfig;
pub use calxgloss_ghidra::GhidraError;
pub use calxgloss_ghidra::ImportsResponse;
pub use calxgloss_ghidra::ListDllsResponse;
pub use calxgloss_ghidra::ListSessionsResponse;
pub use calxgloss_ghidra::Session;
pub use calxgloss_ghidra::CreateSessionResponse;
pub use calxgloss_ghidra::DllInfoResponse;
pub use calxgloss_ghidra::CallgraphResponse;
pub use calxgloss_ghidra::DecompilerResponse;

// ============================================================
// calxgloss-llm — Local LLM client
// ============================================================

pub use calxgloss_llm::LlmClient;
pub use calxgloss_llm::LlmConfig;
pub use calxgloss_llm::LlmError;
pub use calxgloss_llm::LlmMessage;
pub use calxgloss_llm::LlmResponse;
pub use calxgloss_llm::MessageRole;
pub use calxgloss_llm::strip_code_fences;

// ============================================================
// calxgloss-prompts — Prompt templates and rendering
// ============================================================

pub use calxgloss_prompts::error::PromptError;
pub use calxgloss_prompts::TestCaseFormatted;
pub use calxgloss_prompts::TranslateTemplate;
pub use calxgloss_prompts::build_translate_prompt;

// ============================================================
// calxgloss-pal — Platform Abstraction Layer mappings
// ============================================================

pub use calxgloss_pal::ApiMapping;
pub use calxgloss_pal::ApiMappings;
pub use calxgloss_pal::mapping_count;

// ============================================================
// calxgloss-analysis — DLL classification & API tagging
// ============================================================

pub use calxgloss_analysis::classify_dll_name;
pub use calxgloss_analysis::crate_replacement_for;
pub use calxgloss_analysis::DllClassification;
pub use calxgloss_analysis::FunctionAnalysis;
pub use calxgloss_analysis::Strategy;
pub use calxgloss_analysis::Analyzer;
pub use calxgloss_analysis::AnalysisError;
pub use calxgloss_analysis::Result as AnalysisResult;

// ============================================================
// calxgloss-testgen — FFI stubs, test input generation
// ============================================================

pub use calxgloss_testgen::FfiStub;
pub use calxgloss_testgen::FfiStubBuilder;
pub use calxgloss_testgen::generate_ffi_stub;
pub use calxgloss_testgen::parse_signature;
pub use calxgloss_testgen::ParameterTypeInfo;
pub use calxgloss_testgen::DisassemblyEdgeCases;
pub use calxgloss_testgen::EdgeCaseSource;
pub use calxgloss_testgen::generate_test_inputs;
pub use calxgloss_testgen::BaselineRunner;
pub use calxgloss_testgen::TestContext;
pub use calxgloss_testgen::TestGenerator;

// ============================================================
// calxgloss-translator — Translation pipeline
// ============================================================

pub use calxgloss_translator::Translator;
pub use calxgloss_translator::TranslatorError;
pub use calxgloss_translator::Translation;
pub use calxgloss_translator::TranslationPipeline;
pub use calxgloss_translator::Result as TranslatorResult;

// ============================================================
// calxgloss-verify — Compilation and behavioral verification
// ============================================================

pub use calxgloss_verify::CompileResult;
pub use calxgloss_verify::Stubs;

// NOTE: FailedTest, TestCase, and VerificationResult are re-exported
// from calxgloss-types above (calxgloss-verify re-exports them for
// convenience, but we only need one copy)

// ============================================================
// calxgloss-git — Git branch/commit/merge automation
// ============================================================

pub use calxgloss_git::GitManager;
pub use calxgloss_git::InitConfig;
pub use calxgloss_git::BranchResult;
pub use calxgloss_git::MergeResult;
pub use calxgloss_git::PatchRecord;

// ============================================================
// calxgloss-reports — Terminal output formatting
// ============================================================

pub use calxgloss_reports::print_translation_summary;
pub use calxgloss_reports::print_verification_results;
pub use calxgloss_reports::print_git_status;
pub use calxgloss_reports::print_success;
pub use calxgloss_reports::print_failure;
pub use calxgloss_reports::prompt_acceptance;
pub use calxgloss_reports::print_classification_report;
