//! Platform Abstraction Layer — Windows API to cross-platform Rust equivalent mappings.
//!
//! This crate provides a lookup table that maps Windows API calls to their
//! cross-platform Rust equivalents. During translation, every Windows API call
//! is tagged with its category and replaced with the appropriate PAL mapping.
//!
//! # MVP Scope
//!
//! The MVP provides a static mapping table with "PAL placeholder" annotations
//! for non-standard-library APIs. The full system would have platform-specific
//! implementations behind feature flags (`linux`, `macos`, `windows`).
//!
//! # Usage
//!
//! ```
//! use calxgloss_pal::ApiMappings;
//!
//! let mappings = ApiMappings::default();
//!
//! // Look up a specific API
//! if let Some(mapping) = mappings.lookup("CreateFileA") {
//!     println!("Maps to: {}", mapping.rust_equivalent);
//! }
//!
//! // Get all mappings for a category
//! let win32_core = mappings.for_category(calxgloss_types::ApiCategory::Win32Core);
//! assert!(!win32_core.is_empty());
//! ```
use calxgloss_types::ApiCategory;
use indexmap::IndexMap;
use once_cell::sync::Lazy as LazyLock;

/// A single mapping from a Windows API to its cross-platform Rust equivalent.
///
/// Each entry records:
/// - The Windows API name (e.g., `CreateFileA`)
/// - The API category (e.g., `Win32Core`)
/// - The cross-platform Rust equivalent (e.g., `std::fs::File::open`)
/// - Notes explaining the mapping (e.g., "PAL placeholder — not yet implemented")
#[derive(Debug, Clone)]
pub struct ApiMapping {
    /// The Windows API function name (e.g., `CreateFileA`, `Direct3DCreate9`).
    pub windows_api: &'static str,

    /// The platform API category this call belongs to.
    pub category: ApiCategory,

    /// The cross-platform Rust equivalent (e.g., `std::fs::File::open`, `wgpu::Instance [PAL placeholder]`).
    pub rust_equivalent: &'static str,

    /// Human-readable notes about the mapping (e.g., "PAL placeholder — not yet implemented").
    pub notes: &'static str,
}

impl ApiMapping {
    /// Creates a new `ApiMapping` with owned string fields.
    ///
    /// This is useful when mappings need dynamic strings (e.g., from configuration).
    /// For static mappings defined at compile time, prefer using `ApiMappings::default()`.
    pub fn new(
        windows_api: impl Into<String>,
        category: ApiCategory,
        rust_equivalent: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        Self {
            windows_api: windows_api.into().leak(),
            category,
            rust_equivalent: rust_equivalent.into().leak(),
            notes: notes.into().leak(),
        }
    }
}

/// The complete API mapping table.
///
/// This is the central lookup structure used by the analysis and translation
/// crates to determine how to replace Windows API calls with cross-platform
/// Rust equivalents.
///
/// # Default Mappings
///
/// The default implementation provides mappings for the MVP-relevant API categories:
/// - Win32 Core → std lib (fully implemented equivalents)
/// - GDI → tiny-skia (PAL placeholders)
/// - DirectX → wgpu (PAL placeholders)
///
/// # Thread Safety
///
/// `ApiMappings` contains only `&'static str` fields and can be safely shared
/// across threads with `Sync + Send`.
#[derive(Debug, Clone)]
pub struct ApiMappings(&'static [ApiMapping]);

// ============================================================
// Static mapping data — module level for lazy category indexing
// ============================================================

/// Complete list of all Windows API → Rust equivalent mappings.
static MAPPINGS: &[ApiMapping] = &[
    // All mappings defined below — moved here from Default impl
    // ============================================================
    // Win32 Core → std lib
    // ============================================================
    ApiMapping {
        windows_api: "CreateFileA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::File::open",
        notes: "Direct mapping to std::fs::File::open",
    },
    ApiMapping {
        windows_api: "CreateFileW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::File::open",
        notes: "Wide char variant — handle UTF-16 path conversion",
    },
    ApiMapping {
        windows_api: "CreateFile2",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::File::open",
        notes: "Extended CreateFile — map to std::fs with options",
    },
    ApiMapping {
        windows_api: "ReadFile",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::read / std::io::Read",
        notes: "Map to std::fs::read or BufReader::read",
    },
    ApiMapping {
        windows_api: "WriteFile",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::write / std::io::Write",
        notes: "Map to std::fs::write or BufWriter::write",
    },
    ApiMapping {
        windows_api: "CloseHandle",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::io::Drop (Drop trait)",
        notes: "RAII — Rust Drop trait handles cleanup automatically",
    },
    ApiMapping {
        windows_api: "CreateThread",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::thread::spawn",
        notes: "Direct mapping to std::thread::spawn",
    },
    ApiMapping {
        windows_api: "Sleep",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::thread::sleep",
        notes: "Direct mapping to std::thread::sleep",
    },
    ApiMapping {
        windows_api: "VirtualAlloc",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::alloc / mmap crate",
        notes: "PAL placeholder — use std::alloc for managed memory, mmap for raw",
    },
    ApiMapping {
        windows_api: "VirtualFree",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::alloc / mmap crate",
        notes: "PAL placeholder — paired with VirtualAlloc",
    },
    ApiMapping {
        windows_api: "LoadLibraryA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "libloading::Library::load",
        notes: "Dynamic library loading via libloading crate",
    },
    ApiMapping {
        windows_api: "LoadLibraryW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "libloading::Library::load",
        notes: "Wide char variant — handle UTF-16 path conversion",
    },
    ApiMapping {
        windows_api: "GetProcAddress",
        category: ApiCategory::Win32Core,
        rust_equivalent: "libloading::Library::get",
        notes: "Dynamic function resolution via libloading",
    },
    ApiMapping {
        windows_api: "FreeLibrary",
        category: ApiCategory::Win32Core,
        rust_equivalent: "libloading::Library::unload (Drop trait)",
        notes: "RAII — Drop trait handles unloading automatically",
    },
    ApiMapping {
        windows_api: "CreateMutexA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::sync::Mutex",
        notes: "PAL placeholder — std::sync::Mutex for same-process, crossbeam for cross-process",
    },
    ApiMapping {
        windows_api: "CreateMutexW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::sync::Mutex",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "CreateEventA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::sync::Condvar / std::sync::AtomicBool",
        notes: "PAL placeholder — Condvar for wait/notify, AtomicBool for signaling",
    },
    ApiMapping {
        windows_api: "SetEvent",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::sync::Condvar::notify_one / AtomicBool::store",
        notes: "PAL placeholder — paired with CreateEvent",
    },
    ApiMapping {
        windows_api: "WaitForSingleObject",
        category: ApiCategory::Win32Core,
        rust_equivalent: "JoinHandle::join / Condvar::wait",
        notes: "Map to std::thread::JoinHandle::join for threads, Condvar for events",
    },
    ApiMapping {
        windows_api: "GetTickCount",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::time::Instant::now",
        notes: "Monotonic clock — use std::time::Instant",
    },
    ApiMapping {
        windows_api: "GetSystemTime",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::time::SystemTime::now",
        notes: "Wall clock time — use std::time::SystemTime",
    },
    ApiMapping {
        windows_api: "DeleteFileA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::remove_file",
        notes: "Direct mapping to std::fs::remove_file",
    },
    ApiMapping {
        windows_api: "DeleteFileW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::remove_file",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "MoveFileA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::rename",
        notes: "Direct mapping to std::fs::rename",
    },
    ApiMapping {
        windows_api: "MoveFileW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::rename",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "CopyFileA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::copy",
        notes: "Direct mapping to std::fs::copy",
    },
    ApiMapping {
        windows_api: "CopyFileW",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::fs::copy",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "GetFullPathNameA",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::path::Path::canonicalize",
        notes: "PAL placeholder — Path::canonicalize for resolution",
    },
    ApiMapping {
        windows_api: "GetLastError",
        category: ApiCategory::Win32Core,
        rust_equivalent: "std::io::Error::last_os_error",
        notes: "Use std::io::Error for OS-level error handling",
    },
    ApiMapping {
        windows_api: "SetLastError",
        category: ApiCategory::Win32Core,
        rust_equivalent: "(per-thread TLS — not needed in Rust)",
        notes: "Rust does not use thread-local error state — propagate errors via Result",
    },
    // ============================================================
    // GDI → tiny-skia (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "BitBlt",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Pixmap::blit_rect [PAL placeholder]",
        notes: "PAL placeholder — pixel block transfer via tiny-skia",
    },
    ApiMapping {
        windows_api: "StretchBlt",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Pixmap::scale [PAL placeholder]",
        notes: "PAL placeholder — scaled pixel blit via tiny-skia",
    },
    ApiMapping {
        windows_api: "TextOutA",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia + rusttype/skrifa [PAL placeholder]",
        notes: "PAL placeholder — text rendering via tiny-skia + font crate",
    },
    ApiMapping {
        windows_api: "TextOutW",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia + rusttype/skrifa [PAL placeholder]",
        notes: "Wide char variant — handle UTF-16 to UTF-8 conversion",
    },
    ApiMapping {
        windows_api: "Rectangle",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::PathBuilder [PAL placeholder]",
        notes: "PAL placeholder — draw rectangle via tiny-skia path",
    },
    ApiMapping {
        windows_api: "Ellipse",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::PathBuilder [PAL placeholder]",
        notes: "PAL placeholder — draw ellipse via tiny-skia path",
    },
    ApiMapping {
        windows_api: "LineTo",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::PathBuilder [PAL placeholder]",
        notes: "PAL placeholder — draw line via tiny-skia path",
    },
    ApiMapping {
        windows_api: "MoveToEx",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::PathBuilder::move_to [PAL placeholder]",
        notes: "PAL placeholder — set path drawing position",
    },
    ApiMapping {
        windows_api: "CreateCompatibleBitmap",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Pixmap::new [PAL placeholder]",
        notes: "PAL placeholder — create in-memory pixel buffer",
    },
    ApiMapping {
        windows_api: "SelectObject",
        category: ApiCategory::Gdi,
        rust_equivalent: "Use Pixmap directly [PAL placeholder]",
        notes: "PAL placeholder — Rust ownership eliminates GDI select pattern",
    },
    ApiMapping {
        windows_api: "SetTextColor",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Color [PAL placeholder]",
        notes: "PAL placeholder — set drawing color",
    },
    ApiMapping {
        windows_api: "SetBkColor",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Color [PAL placeholder]",
        notes: "PAL placeholder — set background color",
    },
    ApiMapping {
        windows_api: "CreateSolidBrush",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Color [PAL placeholder]",
        notes: "PAL placeholder — color for fills",
    },
    ApiMapping {
        windows_api: "CreatePen",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Pen [PAL placeholder]",
        notes: "PAL placeholder — pen style for strokes",
    },
    ApiMapping {
        windows_api: "GetDC",
        category: ApiCategory::Gdi,
        rust_equivalent: "tiny_skia::Pixmap::new [PAL placeholder]",
        notes: "PAL placeholder — get drawing surface (replaced by Pixmap)",
    },
    ApiMapping {
        windows_api: "ReleaseDC",
        category: ApiCategory::Gdi,
        rust_equivalent: "Pixmap::drop [PAL placeholder]",
        notes: "PAL placeholder — Rust Drop handles cleanup",
    },
    // ============================================================
    // DirectX → wgpu (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "Direct3DCreate9",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Instance::new [PAL placeholder]",
        notes: "PAL placeholder — create wgpu Instance",
    },
    ApiMapping {
        windows_api: "CreateDevice",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Instance::request_adapter + request_device [PAL placeholder]",
        notes: "PAL placeholder — request GPU adapter and device",
    },
    ApiMapping {
        windows_api: "Present",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Queue::submit [PAL placeholder]",
        notes: "PAL placeholder — submit render commands to GPU",
    },
    ApiMapping {
        windows_api: "DrawPrimitive",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPass::draw [PAL placeholder]",
        notes: "PAL placeholder — issue draw call via render pipeline",
    },
    ApiMapping {
        windows_api: "SetTexture",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPass::set_bind_group [PAL placeholder]",
        notes: "PAL placeholder — bind texture to render pass",
    },
    ApiMapping {
        windows_api: "SetRenderState",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPipelineDescriptor [PAL placeholder]",
        notes: "PAL placeholder — configure pipeline at creation time",
    },
    ApiMapping {
        windows_api: "SetVertexShader",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPipelineDescriptor::vertex [PAL placeholder]",
        notes: "PAL placeholder — configure vertex stage of pipeline",
    },
    ApiMapping {
        windows_api: "SetPixelShader",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPipelineDescriptor::fragment [PAL placeholder]",
        notes: "PAL placeholder — configure fragment stage of pipeline",
    },
    ApiMapping {
        windows_api: "CreateTexture2D",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Texture::new [PAL placeholder]",
        notes: "PAL placeholder — create 2D texture",
    },
    ApiMapping {
        windows_api: "CreateBuffer",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Buffer::new [PAL placeholder]",
        notes: "PAL placeholder — create GPU buffer",
    },
    ApiMapping {
        windows_api: "Map",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Queue::write [PAL placeholder]",
        notes: "PAL placeholder — map buffer for CPU write access",
    },
    ApiMapping {
        windows_api: "Unmap",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Queue::submit [PAL placeholder]",
        notes: "PAL placeholder — unmap and submit changes",
    },
    ApiMapping {
        windows_api: "GetBackBuffer",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::Surface::get_current_texture [PAL placeholder]",
        notes: "PAL placeholder — get current frame buffer",
    },
    ApiMapping {
        windows_api: "SetViewport",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPass::set_viewport [PAL placeholder]",
        notes: "PAL placeholder — configure render viewport",
    },
    ApiMapping {
        windows_api: "SetSamplerState",
        category: ApiCategory::DirectX,
        rust_equivalent: "wgpu::RenderPass::set_bind_group [PAL placeholder]",
        notes: "PAL placeholder — configure texture sampling",
    },
    // ============================================================
    // Win32 GUI → winit/egui (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "CreateWindowExA",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "winit::window::Window::new [PAL placeholder]",
        notes: "PAL placeholder — create cross-platform window via winit",
    },
    ApiMapping {
        windows_api: "CreateWindowExW",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "winit::window::Window::new [PAL placeholder]",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "MessageBoxA",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "rfd::MessageDialog [PAL placeholder]",
        notes: "PAL placeholder — native dialog via rfd crate",
    },
    ApiMapping {
        windows_api: "MessageBoxW",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "rfd::MessageDialog [PAL placeholder]",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "ShowWindow",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "winit::window::Window::show [PAL placeholder]",
        notes: "PAL placeholder — show/hide window via winit",
    },
    ApiMapping {
        windows_api: "UpdateWindow",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "winit event loop [PAL placeholder]",
        notes: "PAL placeholder — winit event loop handles redraw",
    },
    ApiMapping {
        windows_api: "GetClientRect",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "winit::window::Window::inner_size [PAL placeholder]",
        notes: "PAL placeholder — get window dimensions",
    },
    ApiMapping {
        windows_api: "DefWindowProcA",
        category: ApiCategory::Win32Gui,
        rust_equivalent: "egui/iced default handler [PAL placeholder]",
        notes: "PAL placeholder — use egui/iced widget event handling",
    },
    // ============================================================
    // Audio → cpal/rodio (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "waveOutOpen",
        category: ApiCategory::Audio,
        rust_equivalent: "cpal::Stream::play [PAL placeholder]",
        notes: "PAL placeholder — audio playback via cpal",
    },
    ApiMapping {
        windows_api: "waveOutWrite",
        category: ApiCategory::Audio,
        rust_equivalent: "cpal::Stream::write [PAL placeholder]",
        notes: "PAL placeholder — write audio samples to stream",
    },
    ApiMapping {
        windows_api: "waveOutClose",
        category: ApiCategory::Audio,
        rust_equivalent: "cpal::Stream::drop [PAL placeholder]",
        notes: "PAL placeholder — Rust Drop handles cleanup",
    },
    ApiMapping {
        windows_api: "DirectSoundCreate8",
        category: ApiCategory::Audio,
        rust_equivalent: "cpal::DefaultDevice [PAL placeholder]",
        notes: "PAL placeholder — create audio output device",
    },
    // ============================================================
    // COM → comfy crate (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "CoInitialize",
        category: ApiCategory::Com,
        rust_equivalent: "comfy::com_init [PAL placeholder]",
        notes: "PAL placeholder — initialize COM library for thread",
    },
    ApiMapping {
        windows_api: "CoUninitialize",
        category: ApiCategory::Com,
        rust_equivalent: "comfy RAII guard drop [PAL placeholder]",
        notes: "PAL placeholder — RAII guard handles uninitialization",
    },
    ApiMapping {
        windows_api: "CoCreateInstance",
        category: ApiCategory::Com,
        rust_equivalent: "comfy::create_com_object [PAL placeholder]",
        notes: "PAL placeholder — create COM object by CLSID",
    },
    ApiMapping {
        windows_api: "IUnknown::QueryInterface",
        category: ApiCategory::Com,
        rust_equivalent: "comfy::ComObject::query_interface [PAL placeholder]",
        notes: "PAL placeholder — COM interface query",
    },
    ApiMapping {
        windows_api: "IUnknown::AddRef",
        category: ApiCategory::Com,
        rust_equivalent: "comfy::ComObject::clone [PAL placeholder]",
        notes: "PAL placeholder — COM reference counting",
    },
    ApiMapping {
        windows_api: "IUnknown::Release",
        category: ApiCategory::Com,
        rust_equivalent: "comfy::ComObject drop [PAL placeholder]",
        notes: "PAL placeholder — Rust Drop handles release",
    },
    // ============================================================
    // Win32 Networking → tokio/std::net
    // ============================================================
    ApiMapping {
        windows_api: "WSAStartup",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net (initialized automatically)",
        notes: "Rust networking crates initialize automatically — no startup needed",
    },
    ApiMapping {
        windows_api: "socket",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpSocket / std::net::TcpStream",
        notes: "Direct mapping to std/net or tokio networking",
    },
    ApiMapping {
        windows_api: "connect",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpStream::connect / std::net::TcpStream::connect",
        notes: "Direct mapping to TCP connect",
    },
    ApiMapping {
        windows_api: "send",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpStream::write / std::net::TcpStream::write",
        notes: "Direct mapping to TCP write",
    },
    ApiMapping {
        windows_api: "recv",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpStream::read / std::net::TcpStream::read",
        notes: "Direct mapping to TCP read",
    },
    ApiMapping {
        windows_api: "closesocket",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "std::net::TcpStream drop [RAII]",
        notes: "Rust Drop handles socket cleanup",
    },
    ApiMapping {
        windows_api: "bind",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpListener::bind / std::net::TcpListener::bind",
        notes: "Direct mapping to TCP bind",
    },
    ApiMapping {
        windows_api: "listen",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpListener::listen",
        notes: "Direct mapping to TCP listen",
    },
    ApiMapping {
        windows_api: "accept",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "tokio::net::TcpListener::accept / std::net::TcpListener::accept",
        notes: "Direct mapping to TCP accept",
    },
    ApiMapping {
        windows_api: "gethostname",
        category: ApiCategory::Win32Networking,
        rust_equivalent: "hostname::get / std::net::UdpSocket::local_addr",
        notes: "PAL placeholder — get local hostname",
    },
    // ============================================================
    // Win32 Registry → directories + serde_json
    // ============================================================
    ApiMapping {
        windows_api: "RegOpenKeyExA",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json [PAL placeholder]",
        notes: "PAL placeholder — use XDG config dir + JSON instead of registry",
    },
    ApiMapping {
        windows_api: "RegOpenKeyExW",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json [PAL placeholder]",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "RegQueryValueExA",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json::from_str [PAL placeholder]",
        notes: "PAL placeholder — read JSON config file",
    },
    ApiMapping {
        windows_api: "RegQueryValueExW",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json::from_str [PAL placeholder]",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "RegSetValueExA",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json::to_string [PAL placeholder]",
        notes: "PAL placeholder — write JSON config file",
    },
    ApiMapping {
        windows_api: "RegSetValueExW",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "directories::ConfigDir + serde_json::to_string [PAL placeholder]",
        notes: "Wide char variant",
    },
    ApiMapping {
        windows_api: "RegCloseKey",
        category: ApiCategory::Win32Registry,
        rust_equivalent: "File drop [RAII]",
        notes: "Rust Drop handles file handle cleanup",
    },
    // ============================================================
    // VB6 Runtime → vb6runtime crate (PAL placeholders for MVP)
    // ============================================================
    ApiMapping {
        windows_api: "SysAllocString",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::BSTR::alloc [PAL placeholder]",
        notes: "PAL placeholder — allocate VB6 BSTR string",
    },
    ApiMapping {
        windows_api: "SysFreeString",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::BSTR::drop [PAL placeholder]",
        notes: "PAL placeholder — free VB6 BSTR string",
    },
    ApiMapping {
        windows_api: "VariantInit",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::VARIANT::empty [PAL placeholder]",
        notes: "PAL placeholder — initialize empty VB6 VARIANT",
    },
    ApiMapping {
        windows_api: "VariantClear",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::VARIANT::clear [PAL placeholder]",
        notes: "PAL placeholder — clear VB6 VARIANT resources",
    },
    ApiMapping {
        windows_api: "DllRegisterServer",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::registry [PAL placeholder]",
        notes: "PAL placeholder — VB6 COM server registration",
    },
    ApiMapping {
        windows_api: "VarI2FromStr",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::variant::i2_from_str [PAL placeholder]",
        notes: "PAL placeholder — VB6 type conversion",
    },
    ApiMapping {
        windows_api: "VarI4FromStr",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::variant::i4_from_str [PAL placeholder]",
        notes: "PAL placeholder — VB6 type conversion",
    },
    ApiMapping {
        windows_api: "VarR8FromStr",
        category: ApiCategory::Vb6Runtime,
        rust_equivalent: "vb6runtime::variant::f8_from_str [PAL placeholder]",
        notes: "PAL placeholder — VB6 type conversion",
    },
];

/// Lazy-initialized category index for efficient `for_category` lookups.
///
/// Built once on first access, then reused. No per-call allocation or leak.
static CATEGORY_INDEX: LazyLock<IndexMap<ApiCategory, Vec<ApiMapping>>> = LazyLock::new(|| {
    let mut map: IndexMap<ApiCategory, Vec<ApiMapping>> = IndexMap::new();
    for mapping in MAPPINGS {
        map.entry(mapping.category.clone())
            .or_default()
            .push(mapping.clone());
    }
    map
});

impl ApiMappings {
    /// Looks up an API mapping by its Windows API name.
    ///
    /// Returns `None` if the API is not in the mapping table.
    ///
    /// # Example
    ///
    /// ```
    /// use calxgloss_pal::ApiMappings;
    /// use calxgloss_types::ApiCategory;
    ///
    /// let mappings = ApiMappings::default();
    /// let mapping = mappings.lookup("CreateFileA");
    /// assert!(mapping.is_some());
    /// assert_eq!(mapping.unwrap().category, ApiCategory::Win32Core);
    /// ```
    pub fn lookup(&self, api: &str) -> Option<&ApiMapping> {
        self.0.iter().find(|m| m.windows_api == api)
    }

    /// Returns all mappings for a given API category.
    ///
    /// Returns an empty slice if no mappings exist for the category.
    ///
    /// # Example
    ///
    /// ```
    /// use calxgloss_pal::ApiMappings;
    /// use calxgloss_types::ApiCategory;
    ///
    /// let mappings = ApiMappings::default();
    /// let win32_core = mappings.for_category(ApiCategory::Win32Core);
    /// assert!(!win32_core.is_empty());
    /// ```
    pub fn for_category(&self, _category: ApiCategory) -> &[ApiMapping] {
        // Use the lazy-initialized category index. No per-call allocation or leak.
        // The IndexMap is built once at first access from the static MAPPINGS.
        CATEGORY_INDEX
            .get(&_category)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns all available API categories that have mappings.
    pub fn available_categories(&self) -> Vec<&ApiCategory> {
        let mut categories: Vec<&ApiCategory> = self.0.iter().map(|m| &m.category).collect();
        categories.dedup_by_key(|c| format!("{:?}", c));
        categories
    }

    /// Returns the total number of mappings in the table.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the mapping table is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over all API mappings.
    pub fn iter(&self) -> impl Iterator<Item = &ApiMapping> {
        self.0.iter()
    }

    /// Returns all API mappings grouped by category for the given set of
    /// categories.
    ///
    /// This is used by the translation pipeline to inject the full mapping
    /// table rows for the specific API categories a function touches into
    /// the LLM prompt (Phase 2, step 2.2 — API-aware prompt augmentation).
    ///
    /// # Arguments
    ///
    /// * `categories` — The API categories to include. Only categories that
    ///   have mappings in the table will appear in the result.
    ///
    /// # Returns
    ///
    /// A vector of [`ApiCategoryMapping`](calxgloss_types::ApiCategoryMapping)
    /// entries, one per requested category that has mappings.
    pub fn for_categories(
        &self,
        categories: &[calxgloss_types::ApiCategory],
    ) -> Vec<calxgloss_types::ApiCategoryMapping> {
        categories
            .iter()
            .filter_map(|cat| {
                let mappings = self.for_category(cat.clone());
                if mappings.is_empty() {
                    return None;
                }
                let items: Vec<calxgloss_types::ApiMappingItem> = mappings
                    .iter()
                    .map(|m| calxgloss_types::ApiMappingItem {
                        windows_api: m.windows_api.to_string(),
                        rust_equivalent: m.rust_equivalent.to_string(),
                        notes: m.notes.to_string(),
                    })
                    .collect();
                Some(calxgloss_types::ApiCategoryMapping {
                    category: cat.to_string(),
                    mappings: items,
                })
            })
            .collect()
    }
}

impl Default for ApiMappings {
    fn default() -> Self {
        // SAFETY: MAPPINGS is a static array defined at module level.
        ApiMappings(MAPPINGS)
    }
}

/// Returns the number of API mappings in the default table.
///
/// This is useful for tests and diagnostics.
pub fn mapping_count() -> usize {
    ApiMappings::default().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mappings_not_empty() {
        let mappings = ApiMappings::default();
        assert!(!mappings.is_empty());
        assert!(mappings.len() > 100);
    }

    #[test]
    fn test_lookup_win32_core() {
        let mappings = ApiMappings::default();
        let mapping = mappings
            .lookup("CreateFileA")
            .expect("CreateFileA should be in mappings");
        assert_eq!(mapping.category, ApiCategory::Win32Core);
        assert_eq!(mapping.windows_api, "CreateFileA");
        assert!(mapping.rust_equivalent.contains("std::fs::File::open"));
    }

    #[test]
    fn test_lookup_gdi() {
        let mappings = ApiMappings::default();
        let mapping = mappings
            .lookup("BitBlt")
            .expect("BitBlt should be in mappings");
        assert_eq!(mapping.category, ApiCategory::Gdi);
        assert!(mapping.rust_equivalent.contains("tiny_skia"));
        assert!(mapping.notes.contains("PAL placeholder"));
    }

    #[test]
    fn test_lookup_directx() {
        let mappings = ApiMappings::default();
        let mapping = mappings
            .lookup("Direct3DCreate9")
            .expect("Direct3DCreate9 should be in mappings");
        assert_eq!(mapping.category, ApiCategory::DirectX);
        assert!(mapping.rust_equivalent.contains("wgpu"));
        assert!(mapping.notes.contains("PAL placeholder"));
    }

    #[test]
    fn test_lookup_not_found() {
        let mappings = ApiMappings::default();
        let result = mappings.lookup("NonExistentFunction");
        assert!(result.is_none());
    }

    #[test]
    fn test_for_category() {
        let mappings = ApiMappings::default();
        let win32_core = mappings.for_category(ApiCategory::Win32Core);
        assert!(!win32_core.is_empty());

        // Should contain known Win32 Core APIs
        let names: Vec<&str> = win32_core.iter().map(|m| m.windows_api).collect();
        assert!(names.contains(&"CreateFileA"));
        assert!(names.contains(&"ReadFile"));
        assert!(names.contains(&"WriteFile"));
    }

    #[test]
    fn test_for_category_empty() {
        let mappings = ApiMappings::default();
        let gdi_plus = mappings.for_category(ApiCategory::GdiPlus);
        assert!(gdi_plus.is_empty());
    }

    #[test]
    fn test_all_categories_have_mappings() {
        let mappings = ApiMappings::default();
        let categories = mappings.available_categories();

        // Verify we have mappings for the key MVP categories
        let category_names: Vec<String> = categories.iter().map(|c| format!("{:?}", c)).collect();
        assert!(category_names.contains(&"Win32Core".to_string()));
        assert!(category_names.contains(&"Gdi".to_string()));
        assert!(category_names.contains(&"DirectX".to_string()));
    }

    #[test]
    fn test_mapping_count_function() {
        assert!(mapping_count() > 100);
    }

    #[test]
    fn test_all_win32_core_apis_have_std_equivalents() {
        let mappings = ApiMappings::default();
        let win32_core = mappings.for_category(ApiCategory::Win32Core);

        for mapping in win32_core {
            // All Win32Core APIs should reference std::, a standard pattern, or RAII
            // Special case: SetLastError is replaced by Result-based error handling in Rust
            let is_valid = mapping.rust_equivalent.contains("std::")
                || mapping.rust_equivalent.contains("libloading")
                || mapping.rust_equivalent.contains("(Rust")
                || mapping.rust_equivalent.contains("Drop")
                || mapping.rust_equivalent.contains("JoinHandle")
                || mapping.rust_equivalent.contains("Condvar")
                || mapping.windows_api == "SetLastError";
            assert!(
                is_valid,
                "Win32Core API '{}' should map to std or RAII pattern, got: '{}'",
                mapping.windows_api, mapping.rust_equivalent
            );
        }
    }

    #[test]
    fn test_all_gdi_apis_are_placeholders() {
        let mappings = ApiMappings::default();
        let gdi = mappings.for_category(ApiCategory::Gdi);

        for mapping in gdi {
            // Wide char variants may reference the ANSI version's notes
            let is_placeholder = mapping.notes.contains("PAL placeholder")
                || mapping.notes.contains("Wide char variant")
                || mapping.rust_equivalent.contains("PAL placeholder");
            assert!(
                is_placeholder,
                "GDI API '{}' should be marked as PAL placeholder",
                mapping.windows_api
            );
        }
    }

    #[test]
    fn test_all_directx_apis_are_placeholders() {
        let mappings = ApiMappings::default();
        let directx = mappings.for_category(ApiCategory::DirectX);

        for mapping in directx {
            assert!(
                mapping.notes.contains("PAL placeholder"),
                "DirectX API '{}' should be marked as PAL placeholder",
                mapping.windows_api
            );
        }
    }

    #[test]
    fn test_mapping_clone_is_identity() {
        let mappings = ApiMappings::default();
        let mapping = mappings.lookup("CreateFileA").expect("should exist");
        let cloned = mapping.clone();
        assert_eq!(mapping.windows_api, cloned.windows_api);
        assert_eq!(mapping.category, cloned.category);
        assert_eq!(mapping.rust_equivalent, cloned.rust_equivalent);
        assert_eq!(mapping.notes, cloned.notes);
    }

    #[test]
    fn test_api_mapping_new() {
        let mapping = ApiMapping::new(
            "TestApi",
            ApiCategory::Win32Core,
            "std::test::function",
            "Test mapping",
        );
        assert_eq!(mapping.windows_api, "TestApi");
        assert_eq!(mapping.category, ApiCategory::Win32Core);
        assert_eq!(mapping.rust_equivalent, "std::test::function");
        assert_eq!(mapping.notes, "Test mapping");
    }

    #[test]
    fn test_wide_char_variants_exist() {
        let mappings = ApiMappings::default();

        // Wide char variants should exist alongside ANSI versions
        assert!(mappings.lookup("CreateFileW").is_some());
        assert!(mappings.lookup("CreateFileA").is_some());
        assert!(mappings.lookup("LoadLibraryW").is_some());
        assert!(mappings.lookup("LoadLibraryA").is_some());
    }

    #[test]
    fn test_is_empty() {
        let mappings = ApiMappings::default();
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_for_categories_returns_mappings_for_multiple_categories() {
        let mappings = ApiMappings::default();

        let categories = vec![ApiCategory::Win32Core, ApiCategory::DirectX];
        let result = mappings.for_categories(&categories);

        assert_eq!(result.len(), 2);

        // Check Win32Core category
        let win32 = result
            .iter()
            .find(|c| c.category == "Win32Core")
            .expect("should have Win32Core");
        assert!(!win32.mappings.is_empty());
        assert!(
            win32
                .mappings
                .iter()
                .any(|m| m.windows_api == "CreateFileA")
        );

        // Check DirectX category
        let dx = result
            .iter()
            .find(|c| c.category == "DirectX")
            .expect("should have DirectX");
        assert!(!dx.mappings.is_empty());
        assert!(
            dx.mappings
                .iter()
                .any(|m| m.windows_api == "Direct3DCreate9")
        );
    }

    #[test]
    fn test_for_categories_empty_input() {
        let mappings = ApiMappings::default();
        let result = mappings.for_categories(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_for_categories_ignores_categories_without_mappings() {
        let mappings = ApiMappings::default();

        // GdiPlus has no mappings
        let categories = vec![ApiCategory::GdiPlus, ApiCategory::Win32Core];
        let result = mappings.for_categories(&categories);

        // Only Win32Core should appear (GdiPlus is filtered out)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].category, "Win32Core");
    }

    #[test]
    fn test_for_categories_api_aware_augmentation() {
        let mappings = ApiMappings::default();

        // Simulate a function that uses GDI APIs
        let categories = vec![ApiCategory::Gdi];
        let result = mappings.for_categories(&categories);

        assert_eq!(result.len(), 1);
        let gdi = &result[0];
        assert_eq!(gdi.category, "GDI");
        assert!(gdi.mappings.iter().any(|m| m.windows_api == "BitBlt"));
        assert!(gdi.mappings.iter().any(|m| m.windows_api == "TextOutA"));
        assert!(
            gdi.mappings
                .iter()
                .any(|m| m.notes.contains("PAL placeholder"))
        );
    }
}
