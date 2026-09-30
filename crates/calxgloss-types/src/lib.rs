//! Shared data structures for the Calxgloss reverse engineering harness.
//!
//! This crate defines the core types used across all Calxgloss crates,
//! including DLL analysis, function metadata, test cases, translation
//! requests/responses, verification results, Git automation, the
//! review dashboard data model, and shim layer API contracts.
//!
//! # Module Organization
//!
//! - [`dll`] — DLL classification and symbol information
//! - [`function`] — Function disassembly, decompiler output, and API tagging
//! - [`shim`] — Shim layer API contract for crate-replacement DLLs
//! - [`test`] — Test case generation and baseline execution
//! - [`translation`] — LLM translation requests and results
//! - [`verification`] — Compilation and behavioral verification results
//! - [`git`] — Branch and commit tracking
//! - [`dashboard`] — Review dashboard data model
//! - [`error`] — Unified error type (`TypesError`)

pub mod complexity;
pub mod dashboard;
pub mod dll;
pub mod error;
pub mod experiment_log;
pub mod function;
pub mod git;
pub mod progress;
pub mod shim;
pub mod test;
pub mod translation;
pub mod verification;

// Re-export public types at the crate root for convenient access.

pub use complexity::{FailureHint, FunctionComplexity, PromptVariant, detect_complexity};
pub use dashboard::{
    DependencyEdge, DependencyGraph, DependencyNode, ReviewAction, ReviewActionKind,
    ReviewDashboard, ReviewStatus, StatusCounts, UnitOfWork, WorkUnitKind,
};
pub use dll::{DllCategory, DllInfo, Export, Import};
pub use shim::{
    ComplexityScore, ReturnMapping, ShimApiMapping, ShimLayer, ShimMappingTestResult,
    ShimVerificationResult, dll_to_module_name,
};
pub use error::TypesError;
pub use experiment_log::{
    CategoryStats, PromptStrategyEntry, PromptStrategyLog, PromptStrategyStats, StrategyStats,
};
pub use function::{ApiCategory, FunctionInfo, WindowsApiCall};
pub use git::{GitBranch, GitCommit};
pub use progress::{ProgressEvent, TranslationEvents};
pub use test::{SideEffect, SideEffectKind, TestCase, TestResult};
pub use translation::{ApiCategoryMapping, ApiMappingItem, TranslationRequest, TranslationResult};
pub use verification::{FailedTest, VerificationResult};

// ============================================================
// Integration tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_category_serialization() {
        let category = DllCategory::MicrosoftSdk;
        let json = serde_json::to_string(&category).unwrap();
        assert_eq!(json, "\"MicrosoftSdk\"");
        let deserialized: DllCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, DllCategory::MicrosoftSdk);
    }

    #[test]
    fn test_api_category_serialization() {
        let category = ApiCategory::DirectX;
        let json = serde_json::to_string(&category).unwrap();
        assert_eq!(json, "\"DirectX\"");
        let deserialized: ApiCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ApiCategory::DirectX);
    }

    #[test]
    fn test_git_branch_new() {
        let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).unwrap();
        assert_eq!(branch.name, "re/game_logic/DrawSpritev1");
        assert_eq!(branch.dll, "game_logic.dll");
        assert_eq!(branch.function, "DrawSprite");
        assert_eq!(branch.attempt, 1);
    }

    #[test]
    fn test_git_branch_empty_dll() {
        let result = GitBranch::new("", "DrawSprite", 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TypesError::EmptyDllName));
    }

    #[test]
    fn test_git_branch_empty_function() {
        let result = GitBranch::new("game_logic.dll", "", 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TypesError::EmptyFunctionName));
    }

    #[test]
    fn test_test_case_serialization() {
        let test_case = TestCase {
            inputs: serde_json::json!({"x": 10, "y": 20}),
            expected_return: serde_json::json!(30),
            expected_side_effects: vec![],
        };
        let json = serde_json::to_string(&test_case).unwrap();
        let deserialized: TestCase = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.inputs["x"], 10);
        assert_eq!(deserialized.expected_return, 30);
    }

    #[test]
    fn test_side_effect_kind_serialization() {
        let kind = SideEffectKind::FileWrite;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"FileWrite\"");
        let deserialized: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, SideEffectKind::FileWrite);
    }

    #[test]
    fn test_side_effect_other_serialization() {
        let kind = SideEffectKind::Other("custom".to_string());
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "{\"Other\":\"custom\"}");
        let deserialized: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized,
            SideEffectKind::Other(ref s) if s == "custom"
        ));
    }

    #[test]
    fn test_translation_result_serialization() {
        let result = TranslationResult {
            rust_code: "fn hello() {}".to_string(),
            prompt_used: "Translate this function...".to_string(),
            model: "qwen3-235b".to_string(),
            tokens_used: Some(4096),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: TranslationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rust_code, "fn hello() {}");
        assert_eq!(deserialized.model, "qwen3-235b");
        assert_eq!(deserialized.tokens_used, Some(4096));
    }

    #[test]
    fn test_shim_api_mapping_serialization() {
        let mapping = ShimApiMapping::new(
            "SetTexture".to_string(),
            "encoder.set_bind_group".to_string(),
            ComplexityScore::Medium,
        );
        let json = serde_json::to_string(&mapping).unwrap();
        let deserialized: ShimApiMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.original_api, "SetTexture");
        assert_eq!(deserialized.crate_api, "encoder.set_bind_group");
        assert_eq!(deserialized.complexity, ComplexityScore::Medium);
    }

    #[test]
    fn test_shim_layer_serialization() {
        let mut shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping::new(
            "Present".to_string(),
            "queue.submit".to_string(),
            ComplexityScore::Low,
        ));
        let json = serde_json::to_string(&shim).unwrap();
        let deserialized: ShimLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_dll, "d3d9.dll");
        assert_eq!(deserialized.target_crate, "wgpu");
        assert_eq!(deserialized.mapping_count(), 1);
    }
}
