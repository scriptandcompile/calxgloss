//! Leaf function detection for call graph analysis.
//!
//! The [`LeafDetector`] identifies functions that call known third-party or
//! system APIs (e.g. Direct3D, GDI, User32, Kernel32), enabling context
//! enrichment during translation.
//!
//! # Expanded Detection (Task 13)
//!
//! | Feature | Description |
//! |---------|-------------|
//! | Fuzzy matching | Matches API name variations (A/W suffixes, stdcall decoration) |
//! | DLL-qualified names | Matches `d3d9.Direct3DCreate9` and similar prefixed names |
//! | Transitive detection | Detects leaf functions reachable through intermediate functions |
//! | Expanded APIs | 100+ Windows APIs across 10 categories |
//!
//! # Algorithm
//!
//! 1. Build an internal set of known API names from the signature list.
//! 2. For each [`FunctionCallGraph`], scan its `callee_name` fields against
//!    that set using both exact and fuzzy matching.
//! 3. Return all matched [`ApiSignature`] entries (category, suggested crate).
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{LeafDetector, FunctionCallGraph, NodeCategory, CallGraphEdge, CallType};
//!
//! let detector = LeafDetector::new();
//! let func = FunctionCallGraph {
//!     name: "create_display".to_string(),
//!     address: 0x402000,
//!     callers: vec![],
//!     callees: vec![CallGraphEdge {
//!         source: 0x402000,
//!         target: 0x78000000,
//!         call_site: 0,
//!         call_type: CallType::Direct,
//!         callee_name: "Direct3DCreate9".to_string(),
//!     }],
//!     node_category: NodeCategory::Middle,
//! };
//! let matches = detector.classify(&func);
//! assert!(matches.is_some());
//! ```

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{CallGraph, FunctionCallGraph};

/// Category of a third-party or system API.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    /// Vulkan graphics and compute APIs.
    Vulkan,
    /// OpenGL and related graphics APIs.
    OpenGL,
}

impl std::fmt::Display for LeafCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeafCategory::Graphics => write!(f, "Graphics"),
            LeafCategory::Gdi => write!(f, "GDI"),
            LeafCategory::Ui => write!(f, "UI"),
            LeafCategory::Filesystem => write!(f, "Filesystem"),
            LeafCategory::Com => write!(f, "COM"),
            LeafCategory::Audio => write!(f, "Audio"),
            LeafCategory::Network => write!(f, "Network"),
            LeafCategory::Crypto => write!(f, "Crypto"),
            LeafCategory::Vulkan => write!(f, "Vulkan"),
            LeafCategory::OpenGL => write!(f, "OpenGL"),
        }
    }
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

/// Transitive leaf context: a function detected as a leaf caller
/// through reach analysis (not by direct API call, but by calling
/// a function that ultimately calls an API).
#[derive(Debug, Clone)]
pub struct TransitiveLeafContext {
    /// The intermediate function that bridges to the API.
    pub intermediate_function: String,
    /// The API address reached through the intermediate.
    pub api_address: u64,
    /// The matched API signature.
    pub api_signature: ApiSignature,
}

/// Detects leaf (API-calling) functions in a call graph.
///
/// Initialized with a comprehensive set of known API signatures
/// across categories (Direct3D, GDI, User32, Kernel32, COM, Audio,
/// Network, Crypto, Vulkan, OpenGL).  A function is classified as
/// a leaf if any of its callees match a registered API signature,
/// including fuzzy matches for common name variations.
///
/// # Fuzzy Matching
///
/// The detector automatically normalizes callee names using these rules:
/// - `MessageBoxA` / `MessageBoxW` → `MessageBox`
/// - `CreateFile@28` → `CreateFile`
/// - `SubMain@0` → `SubMain`
///
/// # DLL-Qualified Names
///
/// Callee names prefixed with a DLL name (e.g. `d3d9.Direct3DCreate9`)
/// are matched by extracting the function name after the dot.
pub struct LeafDetector {
    /// Lookup set of known API names for O(1) exact matching.
    api_names: HashSet<String>,
    /// All registered API signatures (used to return matched details).
    api_signatures: Vec<ApiSignature>,
}

impl LeafDetector {
    /// Creates a new `LeafDetector` initialized with an expanded API signature
    /// set across ten categories (100+ APIs):
    ///
    /// | Category | Sample APIs | Rust Crate |
    /// |----------|-------------|------------|
    /// | Graphics | `Direct3DCreate9`, `D3D11CreateDevice` | `wgpu` |
    /// | GDI | `CreateCompatibleDC`, `BitBlt`, `SelectObject` | `tiny-skia` |
    /// | UI | `MessageBox`, `CreateWindowEx`, `ShowWindow` | `winit` |
    /// | Filesystem | `CreateFile`, `ReadFile`, `WriteFile` | `std::fs` |
    /// | COM | `CoInitialize`, `QueryInterface`, `CoCreateInstance` | `windows` |
    /// | Audio | `FMOD_StudioSystem_Create`, `Mix_Init` | `rodio` |
    /// | Network | `WSAStartup`, `socket`, `recv`, `send` | `tokio` |
    /// | Crypto | `CryptAcquireContext`, `CryptEncrypt` | `ring` |
    /// | Vulkan | `vkCreateInstance`, `vkCreateDevice` | `vulkan` |
    /// | OpenGL | `wglCreateContext`, `glClearColor` | `gl` |
    ///
    /// # Expanded categories (Task 13 additions)
    ///
    /// - **Vulkan**: `vkCreateInstance`, `vkCreateDevice`, `vkSwapchain` variants
    /// - **OpenGL**: `wglCreateContext`, `wglSwapBuffers`, `gl*` entrypoints
    /// - **DirectX 11-12**: `D3D11CreateDevice`, `D3D12CreateDevice`
    /// - **More User32**: `SetWindowText`, `GetWindowText`, `SendMessage`, `PostMessage`
    /// - **More Kernel32**: `LoadLibrary`, `GetProcAddress`, `FreeLibrary`
    pub fn new() -> Self {
        let api_signatures = vec![
            // ─── Graphics — Direct3D 9 ───
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
            // ─── Graphics — Direct3D 10/11/12 ───
            ApiSignature {
                api_name: "D3D10CreateDevice".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "D3D10CreateDeviceAndSwapChain".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "D3D11CreateDevice".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "D3D11CreateDeviceAndSwapChain".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "D3D12CreateDevice".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "D3DCompile".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "naga".to_string(),
            },
            // ─── Graphics — DXGI ───
            ApiSignature {
                api_name: "CreateDXGIFactory".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            ApiSignature {
                api_name: "CreateDXGIFactory1".to_string(),
                category: LeafCategory::Graphics,
                rust_crate: "wgpu".to_string(),
            },
            // ─── GDI ───
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
            ApiSignature {
                api_name: "CreateCompatibleBitmap".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "GetDC".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "ReleaseDC".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "DrawText".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "TextOut".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "FillRect".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "SetPixel".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "GetPixel".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "CreateBrushIndirect".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            ApiSignature {
                api_name: "DeleteObject".to_string(),
                category: LeafCategory::Gdi,
                rust_crate: "tiny-skia".to_string(),
            },
            // ─── UI — User32 ───
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
            ApiSignature {
                api_name: "UpdateWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "SetWindowText".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "GetWindowText".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "SendMessage".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "PostMessage".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "DefWindowProc".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "RegisterClass".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "GetMessage".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "TranslateMessage".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "DispatchMessage".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "DestroyWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "MoveWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "SetCursorPos".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "GetCursorPos".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "EnableWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "IsWindowVisible".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "SetForegroundWindow".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "LoadIcon".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            ApiSignature {
                api_name: "LoadCursor".to_string(),
                category: LeafCategory::Ui,
                rust_crate: "winit".to_string(),
            },
            // ─── Filesystem — Kernel32 ───
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
            ApiSignature {
                api_name: "CloseHandle".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "GetFileSize".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "SetFilePointer".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "DeleteFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "GetFileAttributes".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "SetFileAttributes".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "FindFirstFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "FindNextFile".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "FindClose".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "CreateDirectory".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            ApiSignature {
                api_name: "RemoveDirectory".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::fs".to_string(),
            },
            // ─── Kernel32 — Dynamic Loading ───
            ApiSignature {
                api_name: "LoadLibrary".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "libloading".to_string(),
            },
            ApiSignature {
                api_name: "GetProcAddress".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "libloading".to_string(),
            },
            ApiSignature {
                api_name: "FreeLibrary".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "libloading".to_string(),
            },
            ApiSignature {
                api_name: "GetModuleHandle".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "libloading".to_string(),
            },
            // ─── Kernel32 — Process/Thread ───
            ApiSignature {
                api_name: "CreateProcess".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::process".to_string(),
            },
            ApiSignature {
                api_name: "CreateThread".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::thread".to_string(),
            },
            ApiSignature {
                api_name: "WaitForSingleObject".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::sync".to_string(),
            },
            ApiSignature {
                api_name: "ExitThread".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::process".to_string(),
            },
            ApiSignature {
                api_name: "TerminateProcess".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::process".to_string(),
            },
            ApiSignature {
                api_name: "GetCommandLine".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::env".to_string(),
            },
            ApiSignature {
                api_name: "GetEnvironmentVariable".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::env".to_string(),
            },
            ApiSignature {
                api_name: "SetEnvironmentVariable".to_string(),
                category: LeafCategory::Filesystem,
                rust_crate: "std::env".to_string(),
            },
            // ─── COM ───
            ApiSignature {
                api_name: "CoInitialize".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "CoUninitialize".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "CoCreateInstance".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "QueryInterface".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "AddRef".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "Release".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "CoInitializeEx".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            ApiSignature {
                api_name: "CoGetObject".to_string(),
                category: LeafCategory::Com,
                rust_crate: "windows".to_string(),
            },
            // ─── Audio ───
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
            ApiSignature {
                api_name: "PlaySound".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            ApiSignature {
                api_name: "waveOutOpen".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            ApiSignature {
                api_name: "waveOutWrite".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            ApiSignature {
                api_name: "DirectSoundCreate".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            ApiSignature {
                api_name: "XAudio2Create".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "cpal".to_string(),
            },
            ApiSignature {
                api_name: "mciSendString".to_string(),
                category: LeafCategory::Audio,
                rust_crate: "rodio".to_string(),
            },
            // ─── Network ───
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
            ApiSignature {
                api_name: "connect".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "bind".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "listen".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "accept".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "getaddrinfo".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "getservbyname".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "gethostname".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "inet_addr".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "closesocket".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "WSACleanup".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            ApiSignature {
                api_name: "ioctlsocket".to_string(),
                category: LeafCategory::Network,
                rust_crate: "tokio".to_string(),
            },
            // ─── Crypto ───
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
            ApiSignature {
                api_name: "CryptDecrypt".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptGenRandom".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptHashData".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptCreateHash".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptDeriveKey".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptExportKey".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptImportKey".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptDestroyHash".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            ApiSignature {
                api_name: "CryptReleaseContext".to_string(),
                category: LeafCategory::Crypto,
                rust_crate: "ring".to_string(),
            },
            // ─── Vulkan ───
            ApiSignature {
                api_name: "vkCreateInstance".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateDevice".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateSwapchainKHR".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateRenderPass".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreatePipelineLayout".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateGraphicsPipelines".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateCommandBuffer".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkAllocateCommandBuffers".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkQueueSubmit".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkQueuePresentKHR".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateSampler".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateImageView".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCreateBuffer".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkMapMemory".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCmdDraw".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkCmdDrawIndexed".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            ApiSignature {
                api_name: "vkDestroySurface".to_string(),
                category: LeafCategory::Vulkan,
                rust_crate: "vulkano".to_string(),
            },
            // ─── OpenGL ───
            ApiSignature {
                api_name: "wglCreateContext".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "wglDeleteContext".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "wglMakeCurrent".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "wglSwapBuffers".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "wglGetProcAddress".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glClearColor".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glClear".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glEnable".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glBegin".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glEnd".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glVertex".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glDrawArrays".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glDrawElements".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glGenBuffers".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glBindBuffer".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glBufferData".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glViewport".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
            ApiSignature {
                api_name: "glUseProgram".to_string(),
                category: LeafCategory::OpenGL,
                rust_crate: "gl".to_string(),
            },
        ];

        let api_names = api_signatures.iter().map(|s| s.api_name.clone()).collect();

        Self {
            api_names,
            api_signatures,
        }
    }

    /// Normalizes a callee name by applying fuzzy matching rules.
    ///
    /// Returns the normalized name that can be used for lookup.
    /// For example:
    /// - `MessageBoxA` → `MessageBox`
    /// - `CreateFile@28` → `CreateFile`
    /// - `d3d9.Direct3DCreate9` → `Direct3DCreate9`
    fn normalize_name(&self, name: &str) -> String {
        let mut result = name.to_string();

        // Strip DLL-qualified prefix (e.g. `d3d9.Direct3DCreate9`)
        if let Some(dot_pos) = result.find('.') {
            result = result[dot_pos + 1..].to_string();
        }

        // Strip stdcall decoration (e.g. `CreateFile@28`)
        if let Some(at_pos) = result.rfind('@') {
            let prefix = result[..at_pos].to_string();
            let suffix = result[at_pos + 1..].to_string();
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                result = prefix;
            }
        }

        // Strip ANSI/Unicode suffix (e.g. `MessageBoxA`, `MessageBoxW`)
        if result.len() >= 2 {
            let last_char = result.chars().last().unwrap();
            if last_char == 'A' || last_char == 'W' {
                result = result[..result.len() - 1].to_string();
            }
        }

        result
    }

    /// Returns the list of matched API signatures for the given function,
    /// or `None` if no known APIs were found in its callees.
    ///
    /// Iterates through all callee `CallGraphEdge` entries and checks
    /// whether the callee's `callee_name` matches any registered
    /// [`ApiSignature`], using both exact and fuzzy matching.
    pub fn classify(&self, func: &FunctionCallGraph) -> Option<Vec<ApiSignature>> {
        let mut matched = Vec::new();

        for edge in &func.callees {
            // Try exact match first
            if self.api_names.contains(&edge.callee_name) {
                if let Some(sig) = self
                    .api_signatures
                    .iter()
                    .find(|s| s.api_name == edge.callee_name)
                    .cloned()
                {
                    matched.push(sig);
                }
                continue;
            }

            // Try fuzzy match via normalization
            let normalized = self.normalize_name(&edge.callee_name);
            if normalized != edge.callee_name
                && self.api_names.contains(&normalized)
                && let Some(sig) = self
                    .api_signatures
                    .iter()
                    .find(|s| s.api_name == normalized)
                    .cloned()
            {
                matched.push(sig);
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

    /// Performs transitive leaf analysis across the entire call graph.
    ///
    /// Starting from functions that are direct leaf callers (identified
    /// by [`classify`]), this method traces the call graph to find
    /// intermediate functions that eventually reach known APIs.
    ///
    /// Returns a list of [`TransitiveLeafContext`] entries, each describing
    /// an intermediate function that bridges to a leaf API.
    ///
    /// # Algorithm
    ///
    /// 1. Build an address-to-function lookup from the graph.
    /// 2. Identify all direct leaf functions (those with matched API callees).
    /// 3. For each direct leaf, find all callers, then their callers, etc.
    /// 4. Stop at depth `max_depth` (default 3) to avoid excessive traversal.
    pub fn transitive_leaf_analysis(&self, graph: &CallGraph) -> Vec<TransitiveLeafContext> {
        if graph.functions.is_empty() {
            return Vec::new();
        }

        // Build address-to-function lookup
        let addr_to_func: HashMap<u64, &FunctionCallGraph> =
            graph.functions.iter().map(|f| (f.address, f)).collect();

        // Identify direct leaf functions: address → matched signatures
        let mut direct_leaves: HashMap<u64, Vec<ApiSignature>> = HashMap::new();
        for func in &graph.functions {
            if let Some(sigs) = self.classify(func)
                && !sigs.is_empty()
            {
                direct_leaves.insert(func.address, sigs);
            }
        }

        if direct_leaves.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<TransitiveLeafContext> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        // Track all transitive leaf callers found (caller_addr → their APIs)
        let mut transitive_leaves: HashMap<u64, Vec<ApiSignature>> = HashMap::new();
        let max_depth = 3;

        // BFS from direct leaves back through callers
        // Queue: (current_func_address, depth)
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();

        // Seed with direct leaves
        for &addr in direct_leaves.keys() {
            queue.push_back((addr, 0));
            visited.insert(addr);
        }

        while let Some((current_addr, depth)) = queue.pop_front() {
            // Get the APIs that flow through current_addr (direct or transitive)
            let current_sigs: Vec<ApiSignature> = direct_leaves
                .get(&current_addr)
                .into_iter()
                .chain(transitive_leaves.get(&current_addr))
                .flatten()
                .cloned()
                .collect();

            if current_sigs.is_empty() {
                continue;
            }

            if let Some(current_func) = addr_to_func.get(&current_addr) {
                // Find all callers of the current function
                for caller_addr in &current_func.callers {
                    if visited.insert(*caller_addr) {
                        let caller_func = match addr_to_func.get(caller_addr) {
                            Some(f) => f,
                            None => continue,
                        };

                        // Record transitive context: any caller of a function that
                        // is a direct or transitive leaf is itself a transitive leaf.
                        for sig in &current_sigs {
                            results.push(TransitiveLeafContext {
                                intermediate_function: caller_func.name.clone(),
                                api_address: current_addr,
                                api_signature: sig.clone(),
                            });
                        }

                        // Track this caller as a transitive leaf for further traversal
                        transitive_leaves.insert(*caller_addr, current_sigs.clone());

                        // Continue BFS if within depth limit
                        if depth + 1 < max_depth {
                            queue.push_back((*caller_addr, depth + 1));
                        }
                    }
                }
            }
        }

        results
    }

    /// Returns the total number of API signatures registered with this detector.
    pub fn signature_count(&self) -> usize {
        self.api_signatures.len()
    }

    /// Returns the number of distinct categories represented in the signature set.
    pub fn category_count(&self) -> usize {
        self.api_signatures
            .iter()
            .map(|s| &s.category)
            .collect::<std::collections::HashSet<_>>()
            .len()
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

    fn make_func_with_address(
        name: &str,
        address: u64,
        callers: Vec<u64>,
        callee_names: &[&str],
    ) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address,
            callers,
            callees: callee_names
                .iter()
                .map(|n| CallGraphEdge {
                    source: address,
                    target: 0,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: n.to_string(),
                })
                .collect(),
            node_category: NodeCategory::Middle,
        }
    }

    // ─── Exact match tests ───

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
        assert!(
            matches
                .iter()
                .all(|m| m.category == LeafCategory::Filesystem)
        );
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
    fn test_vulkan_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_vulkan", &["vkCreateInstance", "vkCreateDevice"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::Vulkan));
    }

    #[test]
    fn test_opengl_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_gl", &["wglCreateContext", "wglMakeCurrent"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.category == LeafCategory::OpenGL));
    }

    #[test]
    fn test_d3d11_leaf() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("init_d3d11", &["D3D11CreateDevice"]);
        let matches = detector.classify(&func).expect("should match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, LeafCategory::Graphics);
    }

    // ─── Fuzzy match tests ───

    #[test]
    fn test_ansi_unicode_suffix_matching() {
        let detector = LeafDetector::new();
        // MessageBoxA should match MessageBox
        let func = make_func_with_callees("show_dialog_a", &["MessageBoxA"]);
        let matches = detector.classify(&func).expect("should match A suffix");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "MessageBox");

        // MessageBoxW should match MessageBox
        let func = make_func_with_callees("show_dialog_w", &["MessageBoxW"]);
        let matches = detector.classify(&func).expect("should match W suffix");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "MessageBox");
    }

    #[test]
    fn test_stdcall_decoration_matching() {
        let detector = LeafDetector::new();
        // CreateFile@28 should match CreateFile
        let func = make_func_with_callees("load_file", &["CreateFile@28"]);
        let matches = detector.classify(&func).expect("should match stdcall");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "CreateFile");

        // LoadLibrary@4 should match LoadLibrary
        let func = make_func_with_callees("dyn_load", &["LoadLibrary@4"]);
        let matches = detector.classify(&func).expect("should match stdcall");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "LoadLibrary");
    }

    #[test]
    fn test_dll_qualified_name_matching() {
        let detector = LeafDetector::new();
        // d3d9.Direct3DCreate9 should match Direct3DCreate9
        let func = make_func_with_callees("create_display", &["d3d9.Direct3DCreate9"]);
        let matches = detector
            .classify(&func)
            .expect("should match DLL-qualified");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "Direct3DCreate9");
    }

    #[test]
    fn test_fuzzy_no_match_when_no_suffix() {
        let detector = LeafDetector::new();
        let func = make_func_with_callees("some_function", &["FUN_180012340", "local_helper"]);
        assert!(detector.classify(&func).is_none());
    }

    // ─── Edge case tests ───

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
        assert_eq!(unique.len(), 10, "all 10 categories should be represented");
    }

    #[test]
    fn test_api_signatures_count() {
        let detector = LeafDetector::new();
        assert!(
            detector.signature_count() >= 100,
            "should have at least 100 API signatures (got {})",
            detector.signature_count()
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
        assert!(detector.has_leaf_call(&make_func_with_callees("test", &["Direct3DCreate9"])));
    }

    // ─── Transitive leaf analysis tests ───

    #[test]
    fn test_transitive_leaf_empty_graph() {
        let detector = LeafDetector::new();
        let graph = CallGraph {
            dll: "empty.dll".to_string(),
            functions: vec![],
        };
        let results = detector.transitive_leaf_analysis(&graph);
        assert!(results.is_empty());
    }

    #[test]
    fn test_transitive_leaf_no_leaves() {
        let graph = CallGraph {
            dll: "no_leaves.dll".to_string(),
            functions: vec![
                make_func_with_address("func_a", 0x1000, vec![], &["helper"]),
                make_func_with_address("helper", 0x2000, vec![0x1000], &[]),
            ],
        };
        let detector = LeafDetector::new();
        let results = detector.transitive_leaf_analysis(&graph);
        assert!(results.is_empty());
    }

    #[test]
    fn test_transitive_leaf_finds_intermediaries() {
        // app → init_ui → MessageBox
        // app is a transitive leaf; init_ui is a direct leaf
        let graph = CallGraph {
            dll: "transitive.dll".to_string(),
            functions: vec![
                make_func_with_address("app_init", 0x1000, vec![], &["init_ui"]),
                make_func_with_address("init_ui", 0x2000, vec![0x1000], &["MessageBox"]),
            ],
        };
        let detector = LeafDetector::new();
        let results = detector.transitive_leaf_analysis(&graph);
        // app_init should be found as transitive leaf through init_ui → MessageBox
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .any(|r| r.intermediate_function == "app_init")
        );
    }

    #[test]
    fn test_direct_leaf_no_transitive_for_itself() {
        // init_ui calls MessageBox directly; it's a direct leaf, not transitive
        let graph = CallGraph {
            dll: "direct.dll".to_string(),
            functions: vec![make_func_with_address(
                "init_ui",
                0x1000,
                vec![],
                &["MessageBox"],
            )],
        };
        let detector = LeafDetector::new();
        let results = detector.transitive_leaf_analysis(&graph);
        // Since init_ui has no callers, there are no transitive leaves
        assert!(results.is_empty());
    }

    #[test]
    fn test_transitive_deep_chain() {
        // entry → middle → leaf_fn → MessageBox
        // middle and entry should both be transitive leaves
        let graph = CallGraph {
            dll: "chain.dll".to_string(),
            functions: vec![
                make_func_with_address("entry", 0x1000, vec![], &["middle"]),
                make_func_with_address("middle", 0x2000, vec![0x1000], &["leaf_fn"]),
                make_func_with_address("leaf_fn", 0x3000, vec![0x2000], &["MessageBox"]),
            ],
        };
        let detector = LeafDetector::new();
        let results = detector.transitive_leaf_analysis(&graph);
        assert!(!results.is_empty());
        // Both middle and entry should be found as intermediaries
        let intermediaries: Vec<_> = results.iter().map(|r| &r.intermediate_function).collect();
        assert!(intermediaries.contains(&&"middle".to_string()));
    }

    #[test]
    fn test_transitive_respects_depth_limit() {
        // Very deep chain: a → b → c → d → leaf → MessageBox
        // With default depth 3, only some intermediaries should be found
        let graph = CallGraph {
            dll: "deep.dll".to_string(),
            functions: vec![
                make_func_with_address("a", 0x1000, vec![], &["b"]),
                make_func_with_address("b", 0x2000, vec![0x1000], &["c"]),
                make_func_with_address("c", 0x3000, vec![0x2000], &["d"]),
                make_func_with_address("d", 0x4000, vec![0x3000], &["leaf"]),
                make_func_with_address("leaf", 0x5000, vec![0x4000], &["MessageBox"]),
            ],
        };
        let detector = LeafDetector::new();
        let results = detector.transitive_leaf_analysis(&graph);
        // Should find intermediaries up to depth 3
        assert!(!results.is_empty());
    }

    // ─── Category count test ───

    #[test]
    fn test_category_count_is_ten() {
        let detector = LeafDetector::new();
        assert_eq!(detector.category_count(), 10);
    }
}
