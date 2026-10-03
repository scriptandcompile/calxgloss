//! Root function detection for call graph analysis.
//!
//! The [`RootDetector`] identifies functions that are entry points, runtime
//! initializers, or other special functions that should be skipped or stubbed
//! during translation rather than translated verbatim.

use regex::Regex;
use tracing::debug;

use crate::FunctionCallGraph;

/// Describes how to handle a function matched by a root pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAction {
    /// Skip this function entirely during translation.
    Skip,
    /// Generate a stub implementation instead of translating.
    GenerateStub,
    /// Translate normally despite being a known entry point.
    Translate,
}

/// A single root-detection rule pairing a regex with an action.
pub struct RootPattern {
    /// Regex to match against function names.
    pub name_regex: Regex,
    /// Human-readable description of what this pattern matches.
    pub description: &'static str,
    /// Action to take when a function matches this pattern.
    pub action: RootAction,
}

/// Detects root (entry-point / runtime) functions in a call graph.
///
/// Initialized with a set of regex patterns (e.g. `mainCRTStartup`, `WinMain`,
/// `DllMain`) that identify functions to skip or stub during translation.
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::{RootDetector, FunctionCallGraph, NodeCategory};
///
/// let detector = RootDetector::new();
/// let func = FunctionCallGraph {
///     name: "WinMain".to_string(),
///     address: 0x401000,
///     callers: vec![],
///     callees: vec![],
///     node_category: NodeCategory::Middle,
/// };
/// assert!(detector.is_root(&func));
/// ```
pub struct RootDetector {
    patterns: Vec<RootPattern>,
}

impl RootDetector {
    /// Creates a new `RootDetector` initialized with the MVP root-detection patterns:
    ///
    /// | Pattern name        | Regex                                              | Action   |
    /// |---------------------|----------------------------------------------------|----------|
    /// | C/C++ entry points  | `^(mainCRTStartup\|_main\|WinMain\|WinMain@16\|WinMain@20)$` | `Skip`   |
    /// | DLL entry point     | `^DllMain$`                                         | `Skip`   |
    /// | Generic Ghidra entry| `^entry$`                                           | `Skip`   |
    ///
    /// TODO: Add VB6 runtime patterns: `__vbaInitialize`, `__vbaInit`, `SUBMAIN`
    /// TODO: Add .NET CLR patterns: `__managed_main`, `_CorExeMain`
    /// TODO: Add MinGW patterns: `_start`, `__libc_start_main`
    /// TODO: Add MSVC debug entry: `_RTC_Initialize`
    /// TODO: Add detection via zero callers + entry point address in PE header
    /// TODO: Add known runtime DLL detection (msvcr*.dll, msvbvm60.dll, Qt5*.dll, SDL2.dll)
    /// TODO: Add RuntimeLibrary NodeCategory variant
    /// TODO: Allow user to configure patterns via config file
    pub fn new() -> Self {
        let patterns = vec![
            RootPattern {
                name_regex: Regex::new(
                    r"^(mainCRTStartup|_main|WinMain|WinMain@16|WinMain@20)$",
                )
                .expect("valid MVP root pattern"),
                description: "C/C++ entry point (MSVC/MinGW)",
                action: RootAction::Skip,
            },
            RootPattern {
                name_regex: Regex::new(r"^DllMain$").expect("valid MVP root pattern"),
                description: "DLL entry point",
                action: RootAction::Skip,
            },
            RootPattern {
                name_regex: Regex::new(r"^entry$").expect("valid MVP root pattern"),
                description: "Ghidra generic entry point",
                action: RootAction::Skip,
            },
        ];

        Self { patterns }
    }

    /// Classifies a function by name and returns the appropriate [`RootAction`].
    ///
    /// Iterates through all registered patterns and returns the action for the
    /// first matching pattern. If no pattern matches, returns `RootAction::Translate`.
    pub fn classify(&self, name: &str) -> RootAction {
        for pattern in &self.patterns {
            if pattern.name_regex.is_match(name) {
                debug!(func_name = name, pattern = pattern.description, "Root pattern matched");
                return pattern.action;
            }
        }
        RootAction::Translate
    }

    /// Returns `true` if the given function is classified as a root function.
    pub fn is_root(&self, func: &FunctionCallGraph) -> bool {
        matches!(
            self.classify(&func.name),
            RootAction::Skip | RootAction::GenerateStub
        )
    }
}

impl Default for RootDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeCategory;

    fn make_func(name: &str) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address: 0x1000,
            callers: vec![],
            callees: vec![],
            node_category: NodeCategory::Middle,
        }
    }

    #[test]
    fn test_winmain_is_root() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("WinMain")));
        assert!(detector.is_root(&make_func("WinMain@16")));
        assert!(detector.is_root(&make_func("WinMain@20")));
    }

    #[test]
    fn test_dllmain_is_root() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("DllMain")));
    }

    #[test]
    fn test_ghidra_entry_is_root() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("entry")));
    }

    #[test]
    fn test_normal_function_not_root() {
        let detector = RootDetector::new();
        assert!(!detector.is_root(&make_func("some_function")));
        assert!(!detector.is_root(&make_func("translate_me")));
    }
}
