//! Leaf function detection for call graph analysis.
//!
//! The [`LeafDetector`] identifies functions that call known third-party or
//! system APIs (e.g. Direct3D, GDI, User32, Kernel32), enabling context
//! enrichment during translation.
//!
//! # Algorithm
//!
//! 1. Build an internal set of known API names from the MVP signature list.
//! 2. For each [`FunctionCallGraph`], scan its `callee_name` fields
//!    against that set.
//! 3. Return all matched [`ApiSignature`] entries (category, suggested crate).

use std::collections::HashSet;

use crate::FunctionCallGraph;

/// Category of a third-party or system API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LeafCategory {
    /// Direct3D, DXGI, and related graphics APIs.
    Graphics,
    /// GDI and GDI+ rendering APIs.
    Gdi,
    /// User32, Win32 windowing and UI APIs.
    Ui,
    /// Kernel32 file I/O, process/thread, and memory APIs.
    Filesystem,
    /// COM (Component Object Model) APIs.
    Com,
    /// Audio APIs (e.g. FMOD, XAudio2).
    Audio,
    /// Network APIs (e.g. Winsock).
    Network,
    /// Cryptography APIs (e.g. CryptoAPI).
    Crypto,
}

/// A known third-party or system API signature for leaf detection.
#[derive(Debug, Clone)]
pub struct ApiSignature {
    /// The API function name as it appears in decompiled output.
    pub api_name: String,
    /// The category this API belongs to.
    pub category: LeafCategory,
    /// Suggested Rust crate for cross-platform replacement.
    pub rust_crate: String,
}

/// Detects leaf (API-calling) functions in a call graph.
///
/// Initialized with a set of known API signatures across categories
/// (Direct3D, GDI, User32, Kernel32, COM, Audio, Network, Crypto).
/// A function is classified as a leaf if any of its callees match
/// a registered API signature.
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::{LeafDetector, FunctionCallGraph, NodeCategory, CallGraphEdge, CallType};
///
/// let detector = LeafDetector::new();
/// let func = FunctionCallGraph {
///     name: "create_display".to_string(),
///     address: 0x402000,
///     callers: vec![],
///     callees: vec![CallGraphEdge {
///         source: 0x402000,
///         target: 0x78000000,
///         call_site: 0,
///         call_type: CallType::Direct,
///         callee_name: "Direct3DCreate9".to_string(),
///     }],
///     node_category: NodeCategory::Middle,
/// };
/// let matches = detector.classify(&func);
/// assert!(matches.is_some());
/// ```
pub struct LeafDetector {
    /// Lookup set of known API names for O(1) matching.
    api_names: HashSet<String>,
    /// All registered API signatures (used to return matched details).
    api_signatures: Vec<ApiSignature>,
}

impl LeafDetector {
    /// Creates a new `LeafDetector` initialized with MVP API signatures
    /// across all eight categories (20 APIs):
    ///
    /// | Category     | APIs                                                        | Rust Crate  |
    /// |--------------|-------------------------------------------------------------|-------------|
    /// | Graphics     | `Direct3DCreate9`, `Direct3DCreate9Ex`                      | `wgpu`      |
    /// | Gdi          | `CreateCompatibleDC`, `BitBlt`, `SelectObject`              | `tiny-skia` |
    /// | Ui           | `MessageBox`, `CreateWindowEx`, `ShowWindow`                | `winit`     |
    /// | Filesystem   | `CreateFile`, `ReadFile`, `WriteFile`                       | `std::fs`   |
    /// | Com          | `CoInitialize`, `QueryInterface`, `CoCreateInstance`        | `windows`   |
    /// | Audio        | `FMOD_StudioSystem_Create`, `Mix_Init`                      | `rodio`     |
    /// | Network      | `WSAStartup`, `socket`, `recv`, `send`                      | `tokio`     |
    /// | Crypto       | `CryptAcquireContext`, `CryptEncrypt`                       | `ring`      |
    ///
    /// TODO: Expand to 200+ Windows API signatures (auto-generate from Windows SDK headers)
    /// TODO: Add 3rd-party library signatures: DirectX, Vulkan, OpenAL, SFML, etc.
    /// TODO: Add fuzzy matching for name variations (A/W suffixes, etc.)
    /// TODO: Add call graph reach analysis: if func calls funcA which calls D3D, funcA is also a leaf caller
    /// TODO: Add import table analysis: cross-reference with PE imports for more reliable API detection
    /// TODO: Support DLL-qualified names: `d3d9.Direct3DCreate9`
    pub fn new() -> Self {
        let api_signatures = vec![
            // Graphics — Direct3D
            ApiSignature {
                api_name: "Direct3DCreate9".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "Direct3DCreate9Ex".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            // GDI
            ApiSignature {
                api_name: "CreateCompatibleDC".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "BitBlt".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "SelectObject".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            // User32
            ApiSignature {
                api_name: "MessageBox".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "CreateWindowEx".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "ShowWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            // Kernel32
            ApiSignature {
                api_name: "CreateFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "ReadFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "WriteFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            // COM
            ApiSignature {
                api_name: "CoInitialize".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "QueryInterface".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "CoCreateInstance".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            // Audio
            ApiSignature {
                api_name: "FMOD_StudioSystem_Create".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            ApiSignature {
                api_name: "Mix_Init".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            // Network
            ApiSignature {
                api_name: "WSAStartup".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "socket".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "recv".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "send".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            // Crypto
            ApiSignature {
                api_name: "CryptAcquireContext".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptEncrypt".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
        ];

        let api_names = api_signatures
            .iter()
            .map(|s| s.api_name.clone())
            .collect();

        Self {
            api_names,
            api_signatures,
        }
    }

    /// Returns the list of matched API signatures for the given function,
    /// or `None` if no known APIs were found in its callees.
    ///
    /// Iterates through all callee `CallGraphEdge` entries and checks
    /// whether the callee's `callee_name` matches
    /// any registered [`ApiSignature`].
    pub fn classify(&self, func: &FunctionCallGraph) -> Option<Vec<ApiSignature>> {
        let mut matched = Vec::new();

        for edge in &func.callees {
            if self.api_names.contains(&edge.callee_name) {
                let sig = self
                    .api_signatures
                    .iter()
                    .find(|s| s.api_name == edge.callee_name)
                    .cloned();
                if let Some(sig) = sig {
                    matched.push(sig);
                }
            }
        }

        if matched.is_empty() {
            None
        } else {
            Some(matched)
        }
    }

    /// Returns `true` if the function calls any known third-party or system API.
    pub fn has_leaf_call(&self, func: &FunctionCallGraph) -> bool {
        self.classify(func).is_some()
    }
}

impl Default for LeafDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallGraphEdge, CallType, NodeCategory};

    fn make_func_with_callees(name: &str, callee_names: &[&str]) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address: 0x1000,
            callers: vec![],
            callees: callee_names
                .iter()
                .map(|n| CallGraphEdge {
                    source: 0x1000,
                    target: 0,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: n.to_string(),
                })
                .collect(),
            node_category: NodeCategory::Middle,
        }
    }

    #[test]
    fn test_direct3dcreate9_is_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("create_display", &["Direct3DCreate9"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, LeafCategory::Graphics);
        assert_eq!(matches[0].rust_crate, "wgpu");
    }

    #[test]
    fn test_messagebox_is_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("show_dialog", &["MessageBox"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, LeafCategory::Ui);
        assert_eq!(matches[0].rust_crate, "winit");
    }

    #[test]
    fn test_createfile_is_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("load_config", &["CreateFile", "ReadFile"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        // Both should be Filesystem category
        assert!(matches.iter().all(|m| m.category == LeafCategory::Filesystem));
    }

    #[test]
    fn test_wsa_startup_is_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_network", &["WSAStartup", "socket"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Network));
    }

    #[test]
    fn test_co_create_instance_is_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_com", &["CoInitialize", "CoCreateInstance"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Com));
    }

    #[test]
    fn test_unknown_api_not_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("some_function", &["FUN_180012340", "local_helper"]);
        assert!(detector.classify(&func).is_none());
    }

    #[test]
    fn test_empty_callees_not_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("empty", &[]);
        assert!(detector.classify(&func).is_none());
    }

    #[test]
    fn test_normal_function_not_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("translate_me", &["internal_calc", "format_string"]);
        assert!(!detector.has_leaf_call(&func));
    }

    #[test]
    fn test_multiple_api_categories() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees(
            "complex_init",
            &["MessageBox", "CreateFile", "Direct3DCreate9", "internal_fn"],
        );
        let matches = detector.classify(&func).expect("should match 3 APIs");
        assert_eq!(matches.len(), 3);
        let categories: Vec<_> = matches.iter().map(|m| &m.category).collect();
        assert!(categories.contains(&&LeafCategory::Ui));
        assert!(categories.contains(&&LeafCategory::Filesystem));
        assert!(categories.contains(&&LeafCategory::Graphics));
    }

    #[test]
    fn test_has_leaf_call_positive() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("bitblt_user", &["BitBlt"]);
        assert!(detector.has_leaf_call(&func));
    }

    #[test]
    fn test_has_leaf_call_negative() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("plain_fn", &["helper_fn"]);
        assert!(!detector.has_leaf_call(&func));
    }

    #[test]
    fn test_all_categories_covered() {
        let detector = LeafDetector::new();
        let unique: HashSet<_> = detector
            .api_signatures
            .iter()
            .map(|s| s.category.clone())
            .collect();
        assert_eq!(unique.len(), 8, "all 8 categories should be represented");
    }

    #[test]
    fn test_fmod_audio_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_audio", &["FMOD_StudioSystem_Create"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, LeafCategory::Audio);
        assert_eq!(matches[0].rust_crate, "rodio");
    }

    #[test]
    fn test_crypto_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("encrypt_data", &["CryptAcquireContext", "CryptEncrypt"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Crypto));
    }

    #[test]
    fn test_gdi_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("draw_buffer", &["CreateCompatibleDC", "SelectObject"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Gdi));
    }

    #[test]
    fn test_network_recv_send() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("recv_data", &["recv", "send"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Network));
    }

    #[test]
    fn test_api_signatures_count() {
        let detector = LeafDetector::new();
        assert_eq!(
            detector.api_signatures.len(),
            22,
            "MVP should have 22 API signatures"
        );
    }

    #[test]
    fn test_duplicate_callee_single_match() {
        // If a function calls the same API twice, both edges are returned.
        let detector = LeafDetector::new();
        let func = FunctionCallGraph {
            name: "double_call".to_string(),
            address: 0x1000,
            callers: vec![],
            callees: vec![
                CallGraphEdge {
                    source: 0x1000,
                    target: 0,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "MessageBox".to_string(),
                },
                CallGraphEdge {
                    source: 0x1000,
                    target: 0,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "MessageBox".to_string(),
                },
            ],
            node_category: NodeCategory::Middle,
        };
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.api_name == "MessageBox"));
    }

    #[test]
    fn test_default_constructs() {
        let detector = LeafDetector::default();
        assert!(detector.has_leaf_call(&make_func_with_callees(
            "test",
            &["Direct3DCreate9"]
        )));
    }
}
