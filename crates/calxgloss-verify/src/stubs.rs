//! Stub implementations for common external dependencies.
//!
//! When verifying translated Rust code, the function may call external
//! dependencies that aren't part of the standard library (e.g., PAL traits,
//! platform-specific APIs). This module provides minimal stub implementations
//! that allow the code to compile during verification.
//!
//! These stubs are intentionally minimal — they provide correct type signatures
//! but may not implement full semantic equivalence with the original Windows APIs.
//! The behavioral tests primarily verify the translated function's own logic,
//! not the platform abstraction layer.

/// Provides stub implementations for all known external dependencies.
///
/// Call [`Stubs::all()`](Self::all) to get a complete Rust source file
/// containing all stub implementations concatenated together.
#[derive(Debug, Clone, Default)]
pub struct Stubs;

impl Stubs {
    /// Returns a complete Rust source file containing all stub implementations.
    ///
    /// The stubs are concatenated into a single string that can be written directly
    /// to a `lib.rs` file. They include:
    ///
    /// - Common types: `Color`, `Font`, `Sample`, `Texture`, `WindowHandle`, etc.
    /// - PAL traits: `GraphicsDevice`, `AudioDevice`, `FileSystem`, `WindowManager`
    /// - Stub implementations for each PAL trait
    /// - Threading stubs
    pub fn all() -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            types(),
            pal_traits(),
            graphics_stub(),
            audio_stub(),
            filesystem_stub(),
            window_stub(),
            threading_stub(),
        )
    }
}

/// Common type definitions used by PAL traits and translated functions.
pub fn types() -> String {
    r#"
// ============================================================
// Common type definitions
// ============================================================

/// A color in RGBA format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }
}

/// A font handle for text rendering.
#[derive(Debug, Clone, Default)]
pub struct Font {
    pub family: String,
    pub size: f32,
    pub bold: bool,
    pub italic: bool,
}

/// A sample for audio playback.
#[derive(Debug, Clone)]
pub struct Sample {
    pub data: Vec<f32>,
    pub sample_rate: u32,
    pub channels: u16,
}

impl Sample {
    pub fn new(data: Vec<f32>, sample_rate: u32, channels: u16) -> Self {
        Self { data, sample_rate, channels }
    }
}

/// A texture handle.
#[derive(Debug, Clone, Default)]
pub struct Texture {
    pub width: u32,
    pub height: u32,
    pub format: String,
}

/// A render target handle.
#[derive(Debug, Clone, Default)]
pub struct RenderTarget;

/// A window handle.
#[derive(Debug, Clone, Default)]
pub struct WindowHandle;

/// File open mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMode {
    Read,
    Write,
    Append,
    ReadWrite,
}

impl Default for FileMode {
    fn default() -> Self { Self::Read }
}

/// A file handle.
#[derive(Debug, Clone, Default)]
pub struct FileHandle {
    pub path: String,
    pub mode: FileMode,
}

/// Event type for window events.
#[derive(Debug, Clone, PartialEq)]
pub enum WindowEvent {
    Close,
    Resize(u32, u32),
    KeyDown(char),
    KeyUp(char),
    MouseMove(f32, f32),
    MouseButton(bool),
    Other(String),
}

/// Threading priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadPriority {
    Low,
    Normal,
    High,
}
"#
    .to_string()
}

/// PAL trait definitions.
pub fn pal_traits() -> String {
    r#"
// ============================================================
// PAL (Platform Abstraction Layer) traits
// ============================================================

/// Graphics device abstraction.
/// Maps DirectX/GDI calls to cross-platform graphics APIs (wgpu, tiny-skia).
pub trait GraphicsDevice {
    type Texture;
    type RenderTarget;
    fn create_texture(&mut self, width: u32, height: u32) -> Self::Texture;
    fn blit(&mut self, src: &Self::Texture, dest: &mut Self::RenderTarget);
    fn present(&mut self);
    fn draw_line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, color: Color);
    fn draw_rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Color);
    fn draw_text(&mut self, x: f32, y: f32, text: &str, font: &Font, color: Color);
    fn create_render_target(&mut self, width: u32, height: u32) -> Self::RenderTarget;
    fn destroy_texture(&mut self, texture: Self::Texture);
}

/// Audio device abstraction.
/// Maps DirectSound/XAudio2 calls to cpal/rodio.
pub trait AudioDevice {
    fn play_sample(&mut self, sample: &Sample);
    fn stop(&mut self);
    fn set_volume(&mut self, volume: f32);
    fn pause(&mut self);
    fn resume(&mut self);
    fn is_playing(&self) -> bool;
}

/// File system abstraction.
/// Maps CreateFile/ReadFile/WriteFile to std::fs.
pub trait FileSystem {
    type Handle;
    fn open(&self, path: &str, mode: FileMode) -> Result<Self::Handle, String>;
    fn read(&self, handle: &Self::Handle, buf: &mut [u8]) -> Result<usize, String>;
    fn write(&self, handle: &Self::Handle, data: &[u8]) -> Result<usize, String>;
    fn close(&self, handle: Self::Handle) -> Result<(), String>;
    fn create_dir(&self, path: &str) -> Result<(), String>;
    fn exists(&self, path: &str) -> bool;
    fn delete(&self, path: &str) -> Result<(), String>;
}

/// Window manager abstraction.
/// Maps CreateWindowEx/GetMessage/DispatchMessage to winit.
pub trait WindowManager {
    type Window;
    fn create_window(&mut self, title: &str, width: u32, height: u32) -> Result<Self::Window, String>;
    fn show(&self, window: &Self::Window);
    fn hide(&self, window: &Self::Window);
    fn process_events(&mut self) -> Vec<WindowEvent>;
    fn get_client_size(&self, window: &Self::Window) -> Result<(u32, u32), String>;
    fn destroy_window(&mut self, window: Self::Window);
    fn set_title(&self, window: &Self::Window, title: &str);
}

/// Threading abstraction.
/// Maps CreateThread/WaitForSingleObject/Sleep to std::thread.
pub trait Thread {
    type Handle;
    fn spawn<F, T>(f: F) -> Result<Self::Handle, String>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
    fn join(handle: Self::Handle) -> Result<(), String>;
    fn sleep(duration_ms: u64);
    fn current_id() -> u64;
}
"#
    .to_string()
}

/// Stub implementation of GraphicsDevice.
pub fn graphics_stub() -> String {
    r#"
// ============================================================
// GraphicsDevice stub
// ============================================================

#[derive(Default)]
pub struct GraphicsDeviceStub;

impl GraphicsDevice for GraphicsDeviceStub {
    type Texture = Texture;
    type RenderTarget = RenderTarget;

    fn create_texture(&mut self, _width: u32, _height: u32) -> Self::Texture { Texture::default() }
    fn blit(&mut self, _src: &Self::Texture, _dest: &mut Self::RenderTarget) {}
    fn present(&mut self) {}
    fn draw_line(&mut self, _x1: f32, _y1: f32, _x2: f32, _y2: f32, _color: Color) {}
    fn draw_rect(&mut self, _x: f32, _y: f32, _w: f32, _h: f32, _color: Color) {}
    fn draw_text(&mut self, _x: f32, _y: f32, _text: &str, _font: &Font, _color: Color) {}
    fn create_render_target(&mut self, _width: u32, _height: u32) -> Self::RenderTarget { RenderTarget }
    fn destroy_texture(&mut self, _texture: Self::Texture) {}
}
"#
    .to_string()
}

/// Stub implementation of AudioDevice.
pub fn audio_stub() -> String {
    r#"
// ============================================================
// AudioDevice stub
// ============================================================

#[derive(Default)]
pub struct AudioDeviceStub {
    volume: f32,
    playing: bool,
}

impl AudioDevice for AudioDeviceStub {
    fn play_sample(&mut self, _sample: &Sample) { self.playing = true; }
    fn stop(&mut self) { self.playing = false; }
    fn set_volume(&mut self, volume: f32) { self.volume = volume.max(0.0).min(1.0); }
    fn pause(&mut self) { self.playing = false; }
    fn resume(&mut self) { self.playing = true; }
    fn is_playing(&self) -> bool { self.playing }
}
"#
    .to_string()
}

/// Stub implementation of FileSystem.
pub fn filesystem_stub() -> String {
    r#"
// ============================================================
// FileSystem stub
// ============================================================

#[derive(Default)]
pub struct FileSystemStub;

impl FileSystem for FileSystemStub {
    type Handle = FileHandle;

    fn open(&self, path: &str, mode: FileMode) -> Result<Self::Handle, String> {
        Ok(FileHandle { path: path.to_string(), mode })
    }

    fn read(&self, handle: &Self::Handle, buf: &mut [u8]) -> Result<usize, String> {
        if !std::path::Path::new(&handle.path).exists() { return Ok(0); }
        match std::fs::read(&handle.path) {
            Ok(data) => { let len = std::cmp::min(data.len(), buf.len()); buf[..len].copy_from_slice(&data[..len]); Ok(len) }
            Err(_) => Ok(0),
        }
    }

    fn write(&self, handle: &Self::Handle, data: &[u8]) -> Result<usize, String> {
        std::fs::write(&handle.path, data).map(|_| data.len()).map_err(|e| e.to_string())
    }

    fn close(&self, _handle: Self::Handle) -> Result<(), String> { Ok(()) }
    fn create_dir(&self, path: &str) -> Result<(), String> { std::fs::create_dir_all(path).map_err(|e| e.to_string()) }
    fn exists(&self, path: &str) -> bool { std::path::Path::new(path).exists() }
    fn delete(&self, path: &str) -> Result<(), String> { std::fs::remove_file(path).map_err(|e| e.to_string()) }
}
"#
    .to_string()
}

/// Stub implementation of WindowManager.
pub fn window_stub() -> String {
    r#"
// ============================================================
// WindowManager stub
// ============================================================

#[derive(Default)]
pub struct WindowManagerStub {
    windows: Vec<WindowHandle>,
}

impl WindowManager for WindowManagerStub {
    type Window = WindowHandle;

    fn create_window(&mut self, _title: &str, _width: u32, _height: u32) -> Result<Self::Window, String> {
        self.windows.push(WindowHandle);
        Ok(WindowHandle)
    }
    fn show(&self, _window: &Self::Window) {}
    fn hide(&self, _window: &Self::Window) {}
    fn process_events(&mut self) -> Vec<WindowEvent> { Vec::new() }
    fn get_client_size(&self, _window: &Self::Window) -> Result<(u32, u32), String> { Ok((800, 600)) }
    fn destroy_window(&mut self, _window: Self::Window) { self.windows.clear(); }
    fn set_title(&self, _window: &Self::Window, _title: &str) {}
}
"#
    .to_string()
}

/// Stub implementation of threading operations.
pub fn threading_stub() -> String {
    r#"
// ============================================================
// Threading stub
// ============================================================

/// A handle that wraps any JoinHandle so the stub's Thread::Handle
/// type is uniform regardless of the return type T of spawned closures.
pub struct ThreadHandle(std::thread::JoinHandle<()>);

#[derive(Default)]
pub struct ThreadStub;

impl Thread for ThreadStub {
    type Handle = ThreadHandle;

    fn spawn<F, T>(f: F) -> Result<Self::Handle, String>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // The actual work runs in the original thread; we spawn a wrapper
        // that joins it and returns () so the handle type is uniform.
        let handle = std::thread::spawn(f);
        let wrapper = std::thread::spawn(move || {
            let _ = handle.join();
        });
        Ok(ThreadHandle(wrapper))
    }

    fn join(handle: Self::Handle) -> Result<(), String> {
        handle.0.join().map_err(|e| format!("Thread panic: {:?}", e))
    }

    fn sleep(duration_ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(duration_ms));
    }

    fn current_id() -> u64 {
        // std::thread::current().id().as_u64() is gated behind the
        // `thread_id_value` unstable feature.  Process ID is stable and
        // serves as a unique-enough identifier for stub usage.
        std::process::id() as u64
    }
}
"#
    .to_string()
}
