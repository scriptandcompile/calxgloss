//! Function-level analysis types extracted from Ghidra disassembly.
//!
//! This module defines types for representing individual functions found
//! within a DLL, including their disassembly, decompiler output, Windows API
//! call sites, and call graph neighbors.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Platform-specific category for a Windows API call.
///
/// Each category maps to a cross-platform Rust equivalent via the PAL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    /// Core Win32 APIs (`CreateFile`, `ReadFile`, `CreateThread`, etc.).
    /// Maps to `std::fs`, `std::thread`, `std::sync`, etc.
    Win32Core,

    /// DirectX 9 APIs (`Direct3DCreate9`, `Present`, `DrawPrimitive`).
    /// Maps to `wgpu`.
    DirectX,

    /// DirectX 10/11/12 APIs.
    /// Maps to `wgpu`.
    DirectX10,
    DirectX11,
    DirectX12,

    /// GDI APIs (`BitBlt`, `TextOut`, `Rectangle`, etc.).
    /// Maps to `tiny-skia`.
    Gdi,

    /// GDI+ APIs (higher-level GDI).
    /// Maps to `tiny-skia` / `image`.
    GdiPlus,

    /// Direct2D APIs.
    /// Maps to `tiny-skia`.
    Direct2D,

    /// DirectWrite APIs.
    /// Maps to `skrifa` / `rusttype`.
    DirectWrite,

    /// Win32 GUI APIs (`CreateWindowEx`, `MessageBox`, message handling).
    /// Maps to `winit` + `egui` / `iced`.
    Win32Gui,

    /// Audio APIs (`DirectSound`, `waveOut`).
    /// Maps to `cpal` / `rodio`.
    Audio,

    /// COM APIs (`IUnknown`, `CoCreateInstance`, vtable manipulation).
    /// Maps to the `comfy` crate.
    Com,

    /// Win32 networking (`WSAStartup`, `send`, `recv`).
    /// Maps to `tokio` / `std::net`.
    Win32Networking,

    /// Win32 registry APIs (`RegOpenKey`, `RegQueryValue`).
    /// Maps to `directories` + `serde_json`.
    Win32Registry,

    /// VB6 runtime APIs (`msvbvm60.dll` — BSTR, VARIANT, form model).
    /// Maps to `vb6runtime` crate.
    Vb6Runtime,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiCategory::Win32Core => write!(f, "Win32Core"),
            ApiCategory::DirectX => write!(f, "DirectX"),
            ApiCategory::DirectX10 => write!(f, "DirectX10"),
            ApiCategory::DirectX11 => write!(f, "DirectX11"),
            ApiCategory::DirectX12 => write!(f, "DirectX12"),
            ApiCategory::Gdi => write!(f, "GDI"),
            ApiCategory::GdiPlus => write!(f, "GDI+"),
            ApiCategory::Direct2D => write!(f, "Direct2D"),
            ApiCategory::DirectWrite => write!(f, "DirectWrite"),
            ApiCategory::Win32Gui => write!(f, "Win32Gui"),
            ApiCategory::Audio => write!(f, "Audio"),
            ApiCategory::Com => write!(f, "COM"),
            ApiCategory::Win32Networking => write!(f, "Win32Networking"),
            ApiCategory::Win32Registry => write!(f, "Win32Registry"),
            ApiCategory::Vb6Runtime => write!(f, "VB6Runtime"),
        }
    }
}

/// A single Windows API call identified within a function's disassembly.
///
/// When Ghidra analysis finds a call to a known Windows API, this struct
/// records the API name, its category, and the PAL mapping target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsApiCall {
    /// The Windows API function name (e.g., `CreateFileA`).
    pub name: String,

    /// The platform API category this call belongs to.
    pub category: ApiCategory,

    /// The cross-platform Rust equivalent (e.g., `std::fs::File::open`).
    pub pal_mapping: String,
}

/// Complete analysis information for a single function.
///
/// Aggregates disassembly, decompiler output, identified Windows API calls,
/// and the function's call graph neighbors. This is the primary input to
/// the translation pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// The function's exported or internal name.
    pub name: String,

    /// The virtual address of the function entry point within its DLL.
    pub address: u64,

    /// The DLL this function belongs to.
    pub dll: String,

    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,

    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,

    /// Windows API calls identified within this function, with their PAL mappings.
    pub windows_apis: Vec<WindowsApiCall>,

    /// Names of functions called by (or calling) this function.
    pub call_graph: Vec<String>,
}
