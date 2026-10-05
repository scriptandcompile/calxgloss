//! Function complexity classification for prompt selection.
//!
//! This module defines the [`FunctionComplexity`] enum and provides
//! a [`detect_complexity`] function that classifies functions based
//! on disassembly characteristics (instruction count, call depth,
//! branch density, and API call diversity).
//!
//! The classification drives prompt selection in the translation
//! pipeline — simple functions get minimal prompts, complex
//! functions get rich context from Ghidra.
//!
//! # Complexity Tiers
//!
//! | Tier | Instructions | Prompt | Description |
//! |------|-------------|--------|-------------|
//! | `Minimal` | ≤30 | Minimal | Straightforward logic, few branches |
//! | `Standard` | 31–100 | Standard | Typical function, moderate logic |
//! | `Rich` | 101–300 | Rich with request | Complex control flow, multiple APIs |
//! | `Detailed` | >300 | Detailed (with Ghidra context) | Very complex, needs extra context |

use serde::{Deserialize, Serialize};

/// Complexity classification for a function based on its disassembly.
///
/// The complexity level determines which prompt template and context
/// the translation pipeline sends to the LLM.
///
/// # Tiers
///
/// - **Minimal** — Functions with ≤30 instructions are simple enough that
///   the LLM needs only the disassembly, decompiler output, and baseline tests.
///   Extra context would just add noise.
/// - **Standard** — Functions with 31–100 instructions benefit from the normal
///   prompt with Windows API mappings and baseline tests (the default).
/// - **Rich** — Functions with 101–300 instructions have complex control flow
///   or multiple API dependencies. These get augmented prompts with detailed
///   mapping table rows for the relevant API categories.
/// - **Detailed** — Functions exceeding 300 instructions need maximum context:
///   call graph neighbors, neighboring function code, data structures, and
///   type information in addition to everything in `Rich`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionComplexity {
    /// Minimal context — simple function.
    Minimal,
    /// Standard context — typical function.
    Standard,
    /// Rich context — complex control flow or many APIs.
    Rich,
    /// Detailed context — very complex, needs extra Ghidra data.
    Detailed,
}

impl FunctionComplexity {
    /// Returns the number of instructions that define this complexity tier.
    pub fn threshold(self) -> u64 {
        match self {
            Self::Minimal => 30,
            Self::Standard => 100,
            Self::Rich => 300,
            Self::Detailed => u64::MAX,
        }
    }

    /// Returns a human-readable label for this complexity level.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Rich => "rich",
            Self::Detailed => "detailed",
        }
    }

    /// Returns the prompt variant name for this complexity.
    pub fn prompt_variant(&self) -> &str {
        match self {
            Self::Minimal => "minimal_translate",
            Self::Standard => "translate",
            Self::Rich => "rich_translate",
            Self::Detailed => "detailed_translate",
        }
    }
}

impl std::fmt::Display for FunctionComplexity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Detect the complexity of a function from its disassembly text.
///
/// Complexity is determined by four signals:
///
/// 1. **Instruction count** — Number of non-empty, non-comment lines.
/// 2. **Branch density** — Ratio of branch/jump instructions to total instructions.
///    High density (>30%) bumps complexity up one tier.
/// 3. **Call depth** — Number of distinct function calls (`call` / `invokesym`).
///    Many calls suggest complex behavior.
/// 4. **API diversity** — Number of distinct API categories used.
///    More categories = more context needed.
///
/// The signals are combined with weights: instruction count is primary,
/// branch density and call depth are secondary modifiers, and API diversity
/// is a tertiary modifier.
///
/// # Arguments
///
/// * `disassembly` — Raw disassembly text from Ghidra.
/// * `api_categories` — Distinct API categories used by this function.
///
/// # Returns
///
/// The estimated complexity of the function.
pub fn detect_complexity(disassembly: &str, api_categories: &[String]) -> FunctionComplexity {
    let instruction_count = count_instructions(disassembly);
    let branch_ratio = branch_ratio(disassembly, instruction_count);
    let call_count = count_calls(disassembly);
    let category_count = api_categories.len();

    // Start with a raw score from instruction count
    let base_score = classify_by_instructions(instruction_count);

    // Apply modifiers for secondary signals
    let branch_modifier = match (branch_ratio, base_score) {
        (r, _) if r > 0.35 => 1,            // Very high branch density → +1 tier
        (_, 0) if branch_ratio > 0.15 => 0, // Minimal base with branches stays minimal if low count
        _ => 0,
    };

    let call_modifier = match (call_count, base_score) {
        (c, _) if c > 15 => 1, // Many calls → +1 tier
        (c, 0) if c > 3 => 1,  // Minimal base with some calls → bump to standard
        _ => 0,
    };

    let api_modifier = match (category_count, base_score) {
        (c, _) if c > 5 => 1, // Many different API types → +1 tier
        (c, 0) if c > 0 => 1, // Minimal base with any APIs → bump to standard
        _ => 0,
    };

    // Combine: base score + highest modifier
    let total_modifier = branch_modifier.max(call_modifier).max(api_modifier);

    // Clamp to valid range
    let tiers = [
        FunctionComplexity::Minimal,
        FunctionComplexity::Standard,
        FunctionComplexity::Rich,
        FunctionComplexity::Detailed,
    ];
    let index = base_score
        .saturating_add(total_modifier)
        .min(tiers.len() - 1);
    tiers[index].clone()
}

/// Count executable instructions in disassembly text.
///
/// Skips blank lines, comments (lines starting with `;` or `//`),
/// and address-only lines. Only counts lines that look like instructions.
fn count_instructions(disassembly: &str) -> u64 {
    disassembly
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Skip empty lines, comments, and pure address lines
            if trimmed.is_empty() {
                return false;
            }
            if trimmed.starts_with(';') || trimmed.starts_with("//") {
                return false;
            }
            // Skip address-only lines (e.g., "0x00401000:" or just "0x00401000:")
            // Address-only lines still count if they have an instruction after the colon
            if trimmed.starts_with("0x") && trimmed.contains(':') {
                // Check if there's actual instruction text after the address
                if let Some(after_colon) = trimmed.split_once(':') {
                    return !after_colon.1.trim().is_empty();
                }
                return false;
            }
            // Skip header lines
            let starts_with_equals = trimmed.starts_with("==");
            let starts_with_dashes = trimmed.starts_with("---");

            !(starts_with_equals || starts_with_dashes)
        })
        .count() as u64
}

/// Calculate the ratio of branch/jump instructions to total instructions.
///
/// A high ratio indicates complex control flow with many conditionals.
fn branch_ratio(disassembly: &str, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    let branch_patterns = [
        "je ",
        "jne ",
        "jz ",
        "jnz ",
        "jmp ",
        "jg ",
        "jl ",
        "jge ",
        "jle ",
        "ja ",
        "jb ",
        "jae ",
        "jbe ",
        "js ",
        "jns ",
        "jo ",
        "jno ",
        "jp ",
        "jnp ",
        "loop ",
        "loope ",
        "loopne ",
        "call ",
        "invokesym",
    ];

    let branch_count = disassembly
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            branch_patterns
                .iter()
                .any(|p| trimmed.to_lowercase().contains(p))
        })
        .count() as f64;

    branch_count / total as f64
}

/// Count distinct function calls in disassembly.
///
/// Looks for `call` and `invokesym` patterns which indicate function calls.
fn count_calls(disassembly: &str) -> u64 {
    disassembly
        .lines()
        .filter(|line| {
            let trimmed = line.trim().to_lowercase();
            trimmed.contains("call ") || trimmed.contains("invokesym")
        })
        .count() as u64
}

/// Classify complexity based purely on instruction count.
///
/// This is the primary signal; modifiers from branch density,
/// call count, and API diversity adjust the result upward.
fn classify_by_instructions(count: u64) -> usize {
    if count <= 30 {
        0 // Minimal
    } else if count <= 100 {
        1 // Standard
    } else if count <= 300 {
        2 // Rich
    } else {
        3 // Detailed
    }
}

/// The prompt variant to use for a translation, determined by complexity,
/// API awareness, and failure history.
///
/// This is the output of the strategy selection logic that decides
/// what context the LLM should receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptVariant {
    /// The complexity level of the function.
    pub complexity: FunctionComplexity,

    /// Whether to include API-category-specific mapping table rows.
    pub api_aware: bool,

    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,

    /// The strategy label for experiment tracking.
    pub strategy_label: String,
}

impl PromptVariant {
    /// Create a new prompt variant with the given complexity.
    pub fn new(complexity: FunctionComplexity) -> Self {
        let label = complexity.prompt_variant().to_string();
        Self {
            complexity,
            api_aware: true,
            failure_history: Vec::new(),
            strategy_label: label,
        }
    }

    /// Enable API-aware context augmentation.
    pub fn with_api_aware(mut self, enabled: bool) -> Self {
        self.api_aware = enabled;
        self
    }

    /// Add a failure hint from a previous attempt.
    pub fn with_failure(mut self, hint: FailureHint) -> Self {
        self.failure_history.push(hint);
        self
    }

    /// Set the strategy label for experiment tracking.
    pub fn with_strategy(mut self, label: String) -> Self {
        self.strategy_label = label;
        self
    }

    /// Returns true if this variant needs rich context (rich or detailed complexity).
    pub fn needs_rich_context(&self) -> bool {
        matches!(
            self.complexity,
            FunctionComplexity::Rich | FunctionComplexity::Detailed
        )
    }

    /// Returns true if this variant needs detailed Ghidra context
    /// (call graph, neighbors, data structures).
    pub fn needs_detailed_context(&self) -> bool {
        self.complexity == FunctionComplexity::Detailed
    }
}

/// A hint about a failure in a previous attempt.
///
/// Used to inform the LLM about specific mistakes so it can avoid
/// repeating them. Populated by the failure-informed prompting system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureHint {
    /// The attempt number (1-based).
    pub attempt: u32,

    /// The retry strategy used in that attempt.
    pub strategy: String,

    /// A concise description of what went wrong.
    pub failure_description: String,

    /// The specific fix that was attempted (if any).
    pub fix_attempted: Option<String>,
}

impl FailureHint {
    /// Create a new failure hint.
    pub fn new(attempt: u32, strategy: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            attempt,
            strategy: strategy.into(),
            failure_description: description.into(),
            fix_attempted: None,
        }
    }

    /// Set the specific fix that was attempted.
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix_attempted = Some(fix.into());
        self
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_instructions_empty() {
        assert_eq!(count_instructions(""), 0);
    }

    #[test]
    fn test_count_instructions_basic() {
        let disassembly = "
            0x00401000: mov eax, [esp+4]
            0x00401004: add eax, ebx
            0x00401007: ret
        ";
        assert_eq!(count_instructions(disassembly), 3);
    }

    #[test]
    fn test_count_instructions_skips_comments() {
        let disassembly = "
            0x00401000: mov eax, 0 ; initialize
            0x00401005: add eax, 1 ; increment
        ";
        assert_eq!(count_instructions(disassembly), 2);
    }

    #[test]
    fn test_branch_ratio_high() {
        let disassembly = "
            0x00401000: cmp eax, 0
            0x00401003: je .zero_branch
            0x00401005: jmp .end
            0x00401006: .zero_branch:
            0x00401006: xor eax, eax
            0x00401008: ret
        ";
        let total = count_instructions(disassembly);
        let ratio = branch_ratio(disassembly, total);
        assert!(ratio > 0.3, "Expected high branch ratio, got {}", ratio);
    }

    #[test]
    fn test_count_calls() {
        let disassembly = "
            0x00401000: call CreateFileA
            0x00401005: call ReadFile
            0x0040100a: call WriteFile
            0x0040100f: ret
        ";
        assert_eq!(count_calls(disassembly), 3);
    }

    #[test]
    fn test_classify_by_instructions() {
        assert_eq!(classify_by_instructions(10), 0); // Minimal
        assert_eq!(classify_by_instructions(30), 0); // Minimal (boundary)
        assert_eq!(classify_by_instructions(31), 1); // Standard
        assert_eq!(classify_by_instructions(100), 1); // Standard (boundary)
        assert_eq!(classify_by_instructions(101), 2); // Rich
        assert_eq!(classify_by_instructions(300), 2); // Rich (boundary)
        assert_eq!(classify_by_instructions(301), 3); // Detailed
        assert_eq!(classify_by_instructions(1000), 3); // Detailed
    }

    #[test]
    fn test_detect_complexity_simple() {
        let disassembly = "
            0x00401000: mov eax, [esp+4]
            0x00401004: add eax, ebx
            0x00401007: ret
        ";
        let complexity = detect_complexity(disassembly, &[]);
        assert_eq!(complexity, FunctionComplexity::Minimal);
    }

    #[test]
    fn test_detect_complexity_with_many_apis() {
        let disassembly = "
            0x00401000: mov eax, [esp+4]
            0x00401004: ret
        ";
        // Only 2 instructions, but 4 different API categories → bump to Standard
        let categories = vec![
            "DirectX".to_string(),
            "Gdi".to_string(),
            "Win32Core".to_string(),
            "Win32Gui".to_string(),
        ];
        let complexity = detect_complexity(disassembly, &categories);
        assert_eq!(complexity, FunctionComplexity::Standard);
    }

    #[test]
    fn test_detect_complexity_complex_function() {
        // Generate a disassembly with 50+ instructions
        let lines: Vec<String> = (0..60)
            .map(|i| format!("0x{:08X}: nop", 0x00401000 + i * 4))
            .collect();
        let disassembly = lines.join("\n");

        let complexity = detect_complexity(&disassembly, &[]);
        assert_eq!(complexity, FunctionComplexity::Standard);
    }

    #[test]
    fn test_function_complexity_tiers() {
        assert_eq!(FunctionComplexity::Minimal.threshold(), 30);
        assert_eq!(FunctionComplexity::Standard.threshold(), 100);
        assert_eq!(FunctionComplexity::Rich.threshold(), 300);
        assert_eq!(FunctionComplexity::Detailed.threshold(), u64::MAX);
    }

    #[test]
    fn test_function_complexity_labels() {
        assert_eq!(FunctionComplexity::Minimal.label(), "minimal");
        assert_eq!(FunctionComplexity::Standard.label(), "standard");
        assert_eq!(FunctionComplexity::Rich.label(), "rich");
        assert_eq!(FunctionComplexity::Detailed.label(), "detailed");
    }

    #[test]
    fn test_prompt_variant_default() {
        let variant = PromptVariant::new(FunctionComplexity::Standard);
        assert_eq!(variant.complexity, FunctionComplexity::Standard);
        assert!(variant.api_aware);
        assert!(variant.failure_history.is_empty());
        assert_eq!(variant.strategy_label, "translate");
    }

    #[test]
    fn test_prompt_variant_with_failure_hint() {
        let hint = FailureHint::new(1, "compile_fix", "Wrong parameter type");
        let variant = PromptVariant::new(FunctionComplexity::Standard)
            .with_api_aware(true)
            .with_failure(hint);

        assert_eq!(variant.failure_history.len(), 1);
        assert_eq!(variant.failure_history[0].attempt, 1);
        assert_eq!(variant.failure_history[0].strategy, "compile_fix");
    }

    #[test]
    fn test_prompt_variant_needs_rich_context() {
        let minimal = PromptVariant::new(FunctionComplexity::Minimal);
        let standard = PromptVariant::new(FunctionComplexity::Standard);
        let rich = PromptVariant::new(FunctionComplexity::Rich);
        let detailed = PromptVariant::new(FunctionComplexity::Detailed);

        assert!(!minimal.needs_rich_context());
        assert!(!standard.needs_rich_context());
        assert!(rich.needs_rich_context());
        assert!(detailed.needs_rich_context());
    }

    #[test]
    fn test_prompt_variant_needs_detailed_context() {
        assert!(!PromptVariant::new(FunctionComplexity::Rich).needs_detailed_context());
        assert!(PromptVariant::new(FunctionComplexity::Detailed).needs_detailed_context());
    }

    #[test]
    fn test_failure_hint_with_fix() {
        let hint = FailureHint::new(1, "test_fix", "Wrong return value")
            .with_fix("Added explicit error code check");
        assert_eq!(
            hint.fix_attempted,
            Some("Added explicit error code check".to_string())
        );
    }
}
