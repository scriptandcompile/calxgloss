//! Root function detection for call graph analysis.
//!
//! The [`RootDetector`] identifies functions that are entry points, runtime
//! initializers, or other special functions that should be skipped or stubbed
//! during translation rather than translated verbatim.
//!
//! # Detection Categories
//!
//! | Category | Patterns | Action |
//! |----------|----------|--------|
//! | C/C++ entry points | `mainCRTStartup`, `_main`, `WinMain` (with stdcall variants) | Skip |
//! | DLL entry point | `DllMain` | Skip |
//! | Generic Ghidra entry | `entry` | Skip |
//! | VB6 runtime | `__vbaInitialize`, `__vbaInit`, `SUBMAIN` | Skip |
//! | .NET CLR | `__managed_main`, `_CorExeMain` | Skip |
//! | MinGW runtime | `_start`, `__libc_start_main` | Skip |
//! | MSVC debug | `_RTC_Initialize` | Skip |
//! | Runtime DLL functions | Functions in `msvcr*`, `msvbvm60`, `Qt5*`, `SDL2*` binaries | Skip |
//!
//! # Configurable Patterns
//!
//! The [`ConfigurableRootDetector`] reads root patterns from a JSON file,
//! allowing users to define custom patterns without recompiling:
//!
//! ```json
//! {
//!   "patterns": [
//!     {
//!       "regex": "^custom_entry$",
//!       "description": "Custom entry point",
//!       "action": "Skip"
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{RootDetector, FunctionCallGraph, NodeCategory};
//!
//! let detector = RootDetector::new();
//! let func = FunctionCallGraph {
//!     name: "WinMain".to_string(),
//!     address: 0x401000,
//!     callers: vec![],
//!     callees: vec![],
//!     node_category: NodeCategory::Middle,
//! };
//! assert!(detector.is_root(&func));
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

use crate::FunctionCallGraph;

/// Describes how to handle a function matched by a root pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Configuration for a single root-detection rule (for JSON deserialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootPatternConfig {
    /// Regex pattern to match against function names.
    pub regex: String,
    /// Human-readable description of what this pattern matches.
    pub description: String,
    /// Action to take when a function matches this pattern.
    pub action: RootAction,
}

/// A custom root-detection rule loaded from a configuration file.
/// Differs from [`RootPattern`] in that `description` is heap-allocated.
struct CustomRootPattern {
    name_regex: Regex,
    description: String,
    action: RootAction,
}

/// Configuration file for custom root-detection patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDetectorConfig {
    /// List of custom patterns to add alongside the built-in patterns.
    pub patterns: Vec<RootPatternConfig>,
}

/// Detects root (entry-point / runtime) functions in a call graph.
///
/// Initialized with a comprehensive set of regex patterns covering
/// C/C++ entry points, DLL entry points, VB6, .NET, MinGW, MSVC debug,
/// and generic Ghidra entry functions that identify functions to skip
/// or stub during translation.
///
/// # Built-in patterns
///
/// | Pattern name | Regex | Action |
/// |--------------|-------|--------|
/// | C/C++ entry points | `^(mainCRTStartup\|_main\|WinMain\|WinMain@16\|WinMain@20)$` | `Skip` |
/// | DLL entry point | `^DllMain$` | `Skip` |
/// | Generic Ghidra entry | `^entry$` | `Skip` |
/// | VB6 runtime | `^(__vbaInitialize\|__vbaInit\|SUBMAIN)$` | `Skip` |
/// | .NET CLR | `^(__managed_main\|_CorExeMain)$` | `Skip` |
/// | MinGW runtime | `^(_start\|__libc_start_main)$` | `Skip` |
/// | MSVC debug | `^_RTC_Initialize$` | `Skip` |
pub struct RootDetector {
    patterns: Vec<RootPattern>,
}

impl RootDetector {
    /// Creates a new `RootDetector` initialized with comprehensive
    /// root-detection patterns across multiple runtime ecosystems:
    ///
    /// | Category | Patterns |
    /// |----------|----------|
    /// | C/C++ entry | `mainCRTStartup`, `_main`, `WinMain`, `WinMain@16`, `WinMain@20` |
    /// | DLL entry | `DllMain` |
    /// | Generic | `entry` |
    /// | VB6 | `__vbaInitialize`, `__vbaInit`, `SUBMAIN` |
    /// | .NET CLR | `__managed_main`, `_CorExeMain` |
    /// | MinGW | `_start`, `__libc_start_main` |
    /// | MSVC debug | `_RTC_Initialize` |
    pub fn new() -> Self {
        let patterns = vec![
            // C/C++ entry points (MSVC / MinGW)
            RootPattern {
                name_regex: Regex::new(
                    r"^(mainCRTStartup|_main|WinMain|WinMain@16|WinMain@20)$",
                )
                .expect("valid root pattern"),
                description: "C/C++ entry point (MSVC/MinGW)",
                action: RootAction::Skip,
            },
            // DLL entry point
            RootPattern {
                name_regex: Regex::new(r"^DllMain$").expect("valid root pattern"),
                description: "DLL entry point",
                action: RootAction::Skip,
            },
            // Generic Ghidra entry point
            RootPattern {
                name_regex: Regex::new(r"^entry$").expect("valid root pattern"),
                description: "Ghidra generic entry point",
                action: RootAction::Skip,
            },
            // VB6 runtime functions
            RootPattern {
                name_regex: Regex::new(
                    r"^(__vbaInitialize|__vbaInit|SUBMAIN)$",
                )
                .expect("valid root pattern"),
                description: "VB6 runtime initializer",
                action: RootAction::Skip,
            },
            // .NET CLR entry points
            RootPattern {
                name_regex: Regex::new(
                    r"^(__managed_main|_CorExeMain)$",
                )
                .expect("valid root pattern"),
                description: ".NET CLR entry point",
                action: RootAction::Skip,
            },
            // MinGW runtime entry points
            RootPattern {
                name_regex: Regex::new(
                    r"^(_start|__libc_start_main)$",
                )
                .expect("valid root pattern"),
                description: "MinGW runtime entry point",
                action: RootAction::Skip,
            },
            // MSVC debug runtime
            RootPattern {
                name_regex: Regex::new(r"^_RTC_Initialize$")
                    .expect("valid root pattern"),
                description: "MSVC debug runtime initializer",
                action: RootAction::Skip,
            },
        ];

        Self { patterns }
    }

    /// Returns `true` if the function name matches any of the runtime
    /// library DLL patterns (e.g. `msvcr80.dll`, `msvbvm60.dll`, `Qt5Core.dll`,
    /// `SDL2.dll`).
    ///
    /// This is useful for detecting when an entire binary is a runtime library
    /// rather than an application, allowing the entire graph to be skipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use calxgloss_callgraph::RootDetector;
    ///
    /// let detector = RootDetector::new();
    /// assert!(detector.is_runtime_dll("msvcr80.dll"));
    /// assert!(detector.is_runtime_dll("Qt5Core.dll"));
    /// assert!(detector.is_runtime_dll("SDL2.dll"));
    /// assert!(!detector.is_runtime_dll("myapp.dll"));
    /// ```
    pub fn is_runtime_dll(&self, dll_name: &str) -> bool {
        let lower = dll_name.to_lowercase();
        // MSVC runtime DLLs: msvcr*.dll (e.g. msvcr70.dll, msvcr100.dll)
        if lower.starts_with("msvcr") && lower.ends_with(".dll") {
            return true;
        }
        // VB6 runtime
        if lower.contains("msvbvm") {
            return true;
        }
        // Qt runtime libraries
        if lower.starts_with("qt5") || lower.starts_with("qt6") {
            return true;
        }
        // SDL2
        if lower.starts_with("sdl2") {
            return true;
        }
        false
    }

    /// Classifies a function by name and returns the appropriate [`RootAction`].
    ///
    /// Iterates through all registered patterns and returns the action for the
    /// first matching pattern. If no pattern matches, returns `RootAction::Translate`.
    pub fn classify(&self, name: &str) -> RootAction {
        for pattern in &self.patterns {
            if pattern.name_regex.is_match(name) {
                debug!(func_name = name, pattern = %pattern.description, "Root pattern matched");
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

    /// Returns an iterator over all registered pattern descriptions.
    pub fn pattern_descriptions(&self) -> impl Iterator<Item = &str> {
        self.patterns.iter().map(|p| p.description)
    }
}

impl Default for RootDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`RootDetector`] extended with user-configurable patterns loaded from a JSON file.
///
/// The configurable detector always includes the built-in patterns from
/// [`RootDetector`], then adds any additional patterns defined in the
/// configuration file.  This allows users to extend detection without
/// recompiling.
///
/// # Configuration file format
///
/// The configuration is a JSON object with a `patterns` array.  Each
/// pattern has a `regex`, `description`, and `action` field:
///
/// ```json
/// {
///   "patterns": [
///     {
///       "regex": "^custom_entry$",
///       "description": "Custom application entry",
///       "action": "Skip"
///     },
///     {
///       "regex": "^stub_for_.*$",
///       "description": "Stub functions",
///       "action": "GenerateStub"
///     }
///   ]
/// }
/// ```
///
/// Valid actions are `"Skip"`, `"GenerateStub"`, and `"Translate"`.
pub struct ConfigurableRootDetector {
    /// The built-in detector with all standard patterns.
    inner: RootDetector,
    /// Additional patterns loaded from the configuration file.
    custom_patterns: Vec<CustomRootPattern>,
}

impl ConfigurableRootDetector {
    /// Creates a new configurable detector with only the built-in patterns.
    pub fn new() -> Self {
        Self {
            inner: RootDetector::new(),
            custom_patterns: Vec::new(),
        }
    }

    /// Loads custom patterns from a JSON configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read.
    /// - The JSON is malformed.
    /// - Any regex in the patterns is invalid.
    pub fn from_config_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config: RootDetectorConfig =
            serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let mut custom_patterns = Vec::new();

        for cfg in config.patterns {
            let regex = Regex::new(&cfg.regex)?;
            custom_patterns.push(CustomRootPattern {
                name_regex: regex,
                description: cfg.description,
                action: cfg.action,
            });
        }

        debug!(
            custom_count = custom_patterns.len(),
            "Loaded custom root patterns from config"
        );

        Ok(Self {
            inner: RootDetector::new(),
            custom_patterns,
        })
    }

    /// Loads custom patterns from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or any regex is invalid.
    pub fn from_config_str(json: &str) -> anyhow::Result<Self> {
        let config: RootDetectorConfig = serde_json::from_str(json)?;
        let mut custom_patterns = Vec::new();

        for cfg in config.patterns {
            let regex = Regex::new(&cfg.regex)?;
            custom_patterns.push(CustomRootPattern {
                name_regex: regex,
                description: cfg.description,
                action: cfg.action,
            });
        }

        Ok(Self {
            inner: RootDetector::new(),
            custom_patterns,
        })
    }

    /// Checks whether the binary is a known runtime library.
    pub fn is_runtime_dll(&self, dll_name: &str) -> bool {
        self.inner.is_runtime_dll(dll_name)
    }

    /// Classifies a function by name, checking both built-in and custom patterns.
    ///
    /// Built-in patterns are checked first, then custom patterns in the order
    /// they appear in the configuration file.
    pub fn classify(&self, name: &str) -> RootAction {
        // Check built-in patterns first
        match self.inner.classify(name) {
            RootAction::Translate => {}
            action => return action,
        }
        // Then check custom patterns
        for pattern in &self.custom_patterns {
            if pattern.name_regex.is_match(name) {
                debug!(
                    func_name = name,
                    pattern = %pattern.description,
                    "Custom root pattern matched"
                );
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

    /// Returns the number of custom patterns loaded from configuration.
    pub fn custom_pattern_count(&self) -> usize {
        self.custom_patterns.len()
    }

    /// Returns an iterator over all pattern descriptions (built-in + custom).
    pub fn pattern_descriptions(&self) -> impl Iterator<Item = &str> {
        self.inner
            .pattern_descriptions()
            .chain(self.custom_patterns.iter().map(|p| p.description.as_str()))
    }
}

impl Default for ConfigurableRootDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address: 0x1000,
            callers: vec![],
            callees: vec![],
            node_category: crate::NodeCategory::Middle,
        }
    }

    // ─── Built-in root detector tests ───

    #[test]
    fn test_c_cpp_entry_points() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("mainCRTStartup")));
        assert!(detector.is_root(&make_func("_main")));
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
    fn test_vb6_runtime_patterns() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("__vbaInitialize")));
        assert!(detector.is_root(&make_func("__vbaInit")));
        assert!(detector.is_root(&make_func("SUBMAIN")));
    }

    #[test]
    fn test_dotnet_clr_patterns() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("__managed_main")));
        assert!(detector.is_root(&make_func("_CorExeMain")));
    }

    #[test]
    fn test_mingw_patterns() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("_start")));
        assert!(detector.is_root(&make_func("__libc_start_main")));
    }

    #[test]
    fn test_msvc_debug_pattern() {
        let detector = RootDetector::new();
        assert!(detector.is_root(&make_func("_RTC_Initialize")));
    }

    #[test]
    fn test_normal_function_not_root() {
        let detector = RootDetector::new();
        assert!(!detector.is_root(&make_func("some_function")));
        assert!(!detector.is_root(&make_func("translate_me")));
        assert!(!detector.is_root(&make_func("app_init")));
    }

    #[test]
    fn test_runtime_dll_detection() {
        let detector = RootDetector::new();
        // MSVC runtimes
        assert!(detector.is_runtime_dll("msvcr70.dll"));
        assert!(detector.is_runtime_dll("msvcr80.dll"));
        assert!(detector.is_runtime_dll("msvcr100.dll"));
        assert!(detector.is_runtime_dll("MSVCR90.DLL")); // case-insensitive
        // VB6 runtime
        assert!(detector.is_runtime_dll("msvbvm60.dll"));
        assert!(detector.is_runtime_dll("MSVBVM60.DLL"));
        // Qt runtimes
        assert!(detector.is_runtime_dll("Qt5Core.dll"));
        assert!(detector.is_runtime_dll("Qt5Gui.dll"));
        assert!(detector.is_runtime_dll("Qt6Core.dll"));
        assert!(detector.is_runtime_dll("qt5widgets.dll")); // case-insensitive prefix
        // SDL2
        assert!(detector.is_runtime_dll("SDL2.dll"));
        assert!(detector.is_runtime_dll("sdl2.dll"));
        // Non-runtime
        assert!(!detector.is_runtime_dll("myapp.dll"));
        assert!(!detector.is_runtime_dll("game.dll"));
        assert!(!detector.is_runtime_dll("user32.dll"));
    }

    #[test]
    fn test_classify_returns_correct_action() {
        let detector = RootDetector::new();
        assert_eq!(detector.classify("WinMain"), RootAction::Skip);
        assert_eq!(detector.classify("__vbaInitialize"), RootAction::Skip);
        assert_eq!(detector.classify("__managed_main"), RootAction::Skip);
        assert_eq!(detector.classify("app_init"), RootAction::Translate);
    }

    #[test]
    fn test_pattern_descriptions() {
        let detector = RootDetector::new();
        let descs: Vec<_> = detector.pattern_descriptions().collect();
        assert_eq!(descs.len(), 7);
        assert!(descs.contains(&"C/C++ entry point (MSVC/MinGW)"));
        assert!(descs.contains(&"VB6 runtime initializer"));
        assert!(descs.contains(&".NET CLR entry point"));
    }

    // ─── Configurable root detector tests ───

    #[test]
    fn test_configurable_builtin_also_works() {
        let detector = ConfigurableRootDetector::new();
        assert!(detector.is_root(&make_func("WinMain")));
        assert!(detector.is_root(&make_func("DllMain")));
        assert!(detector.is_root(&make_func("__vbaInitialize")));
    }

    #[test]
    fn test_configurable_custom_patterns() {
        let config_json = r#"{
            "patterns": [
                {
                    "regex": "^stub_for_.*$",
                    "description": "Stub functions",
                    "action": "GenerateStub"
                },
                {
                    "regex": "^custom_entry$",
                    "description": "Custom entry",
                    "action": "Skip"
                }
            ]
        }"#;

        let detector = ConfigurableRootDetector::from_config_str(config_json).unwrap();
        assert_eq!(detector.custom_pattern_count(), 2);

        // Built-in patterns still work
        assert!(detector.is_root(&make_func("WinMain")));
        // Custom patterns work
        assert!(detector.is_root(&make_func("stub_for_something")));
        assert!(detector.is_root(&make_func("custom_entry")));
        // Non-matching
        assert!(!detector.is_root(&make_func("app_logic")));

        // Check actions are correct
        assert_eq!(
            detector.classify("stub_for_something"),
            RootAction::GenerateStub
        );
        assert_eq!(detector.classify("custom_entry"), RootAction::Skip);
        assert_eq!(detector.classify("app_logic"), RootAction::Translate);
    }

    #[test]
    fn test_configurable_pattern_count() {
        let detector = ConfigurableRootDetector::new();
        assert_eq!(detector.custom_pattern_count(), 0);
    }

    #[test]
    fn test_configurable_pattern_descriptions_combined() {
        let config_json = r#"{
            "patterns": [
                {
                    "regex": "^custom$",
                    "description": "Custom pattern",
                    "action": "Skip"
                }
            ]
        }"#;

        let detector = ConfigurableRootDetector::from_config_str(config_json).unwrap();
        let descs: Vec<_> = detector.pattern_descriptions().collect();
        assert!(descs.contains(&"Custom pattern"));
        // Built-in patterns are also included
        assert!(descs.contains(&"C/C++ entry point (MSVC/MinGW)"));
    }

    #[test]
    fn test_configurable_invalid_regex_returns_error() {
        let config_json = r#"{
            "patterns": [
                {
                    "regex": "[invalid",
                    "description": "Bad regex",
                    "action": "Skip"
                }
            ]
        }"#;

        let result = ConfigurableRootDetector::from_config_str(config_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_configurable_invalid_json_returns_error() {
        let result = ConfigurableRootDetector::from_config_str("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_configurable_default_constructs() {
        let detector = ConfigurableRootDetector::default();
        assert_eq!(detector.custom_pattern_count(), 0);
        assert!(detector.is_root(&make_func("WinMain")));
    }
}
