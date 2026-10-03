//! Leaf function detection for call graph analysis.
//!
//! The [`LeafDetector`] identifies functions that call known third-party or
//! system APIs (e.g. Direct3D, GDI, User32, Kernel32), enabling context
//! enrichment during translation.

use crate::FunctionCallGraph;

/// Category of a third-party or system API.
#[derive(Debug, Clone, PartialEq, Eq)]
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
///     }],
///     node_category: NodeCategory::Middle,
/// };
/// // In practice, check callees against API names.
/// ```
pub struct LeafDetector {
    /// Known API signatures indexed by name for fast lookup.
    api_signatures: Vec<ApiSignature>,
}

impl LeafDetector {
    /// Creates a new `LeafDetector` initialized with MVP API signatures
    /// across all eight categories (~20 APIs):
    ///
    /// | Category    | Example APIs                        | Rust Crate |
    /// |-------------|-------------------------------------|------------|
    /// | Graphics    | `Direct3DCreate9`                   | `wgpu`     |
    /// | Gdi         | `CreateCompatibleDC`, `BitBlt`      | `tiny-skia`|
    /// | Ui          | `MessageBox`, `CreateWindowEx`      | `winit`    |
    /// | Filesystem  | `CreateFile`, `ReadFile`            | `std::fs`  |
    /// | Com         | `CoInitialize`, `QueryInterface`    | `windows`  |
    /// | Audio       | `FMOD_StudioSystem_Create`          | `rodio`    |
    /// | Network     | `WSAStartup`, `socket`              | `tokio`    |
    /// | Crypto      | `CryptAcquireContext`               | `ring`     |
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
            // Audio
            ApiSignature {
                api_name: "FMOD_StudioSystem_Create".to_string(),
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
            // Crypto
            ApiSignature {
                api_name: "CryptAcquireContext".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
        ];

        Self { api_signatures }
    }

    /// Returns the list of matched API signatures for the given function,
    /// or `None` if no known APIs were found in its callees.
    ///
    /// Iterates through all callee `CallGraphEdge` entries and checks
    /// whether the callee's name matches any registered [`ApiSignature`].
    pub fn classify(
        &self,
        func: &FunctionCallGraph,
    ) -> Option<Vec<ApiSignature>> {
        // TODO: Look up callee names from decompiled output against api_signatures
        let _func_name = &func.name;
        // TODO: Cross-reference func.callees with api_signatures
        unimplemented!()
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
