//! Static API mapping data.
//!
//! This module holds the `MAPPINGS` array and the `CATEGORY_INDEX` lazy
//! initialisation. It is a separate module so that the mapping table
//! definition doesn't bloat `lib.rs` beyond easy browsing.

use calxgloss_types::ApiCategory;
use indexmap::IndexMap;
use once_cell::sync::Lazy as LazyLock;

use crate::ApiMapping;

// ============================================================
// Static mapping data — module level for lazy category indexing
// ============================================================

/// Complete list of all Windows API → Rust equivalent mappings.
pub static MAPPINGS: &[ApiMapping] = &[
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
pub static CATEGORY_INDEX: LazyLock<IndexMap<ApiCategory, Vec<ApiMapping>>> =
    LazyLock::new(|| {
        let mut map: IndexMap<ApiCategory, Vec<ApiMapping>> = IndexMap::new();
        for mapping in MAPPINGS {
            map.entry(mapping.category.clone())
                .or_default()
                .push(mapping.clone());
        }
        map
    });
