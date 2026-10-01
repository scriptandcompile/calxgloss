//! Common type definitions and PAL (Platform Abstraction Layer) traits.
//! Provides common type definitions and traits for platform abstraction.

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
        Self {
            data,
            sample_rate,
            channels,
        }
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
    fn default() -> Self {
        Self::Read
    }
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
    fn create_window(
        &mut self,
        title: &str,
        width: u32,
        height: u32,
    ) -> Result<Self::Window, String>;
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

// ============================================================
// GraphicsDevice stub
// ============================================================

#[derive(Default)]
pub struct GraphicsDeviceStub;

impl GraphicsDevice for GraphicsDeviceStub {
    type Texture = Texture;
    type RenderTarget = RenderTarget;

    fn create_texture(&mut self, _width: u32, _height: u32) -> Self::Texture {
        Texture::default()
    }
    fn blit(&mut self, _src: &Self::Texture, _dest: &mut Self::RenderTarget) {}
    fn present(&mut self) {}
    fn draw_line(&mut self, _x1: f32, _y1: f32, _x2: f32, _y2: f32, _color: Color) {}
    fn draw_rect(&mut self, _x: f32, _y: f32, _w: f32, _h: f32, _color: Color) {}
    fn draw_text(&mut self, _x: f32, _y: f32, _text: &str, _font: &Font, _color: Color) {}
    fn create_render_target(&mut self, _width: u32, _height: u32) -> Self::RenderTarget {
        RenderTarget
    }
    fn destroy_texture(&mut self, _texture: Self::Texture) {}
}

// ============================================================
// AudioDevice stub
// ============================================================

#[derive(Default)]
pub struct AudioDeviceStub {
    volume: f32,
    playing: bool,
}

impl AudioDevice for AudioDeviceStub {
    fn play_sample(&mut self, _sample: &Sample) {
        self.playing = true;
    }
    fn stop(&mut self) {
        self.playing = false;
    }
    fn set_volume(&mut self, volume: f32) {
        self.volume = volume.max(0.0).min(1.0);
    }
    fn pause(&mut self) {
        self.playing = false;
    }
    fn resume(&mut self) {
        self.playing = true;
    }
    fn is_playing(&self) -> bool {
        self.playing
    }
}

// ============================================================
// FileSystem stub
// ============================================================

#[derive(Default)]
pub struct FileSystemStub;

impl FileSystem for FileSystemStub {
    type Handle = FileHandle;

    fn open(&self, path: &str, mode: FileMode) -> Result<Self::Handle, String> {
        Ok(FileHandle {
            path: path.to_string(),
            mode,
        })
    }

    fn read(&self, handle: &Self::Handle, buf: &mut [u8]) -> Result<usize, String> {
        if !std::path::Path::new(&handle.path).exists() {
            return Ok(0);
        }
        match std::fs::read(&handle.path) {
            Ok(data) => {
                let len = std::cmp::min(data.len(), buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            Err(_) => Ok(0),
        }
    }

    fn write(&self, handle: &Self::Handle, data: &[u8]) -> Result<usize, String> {
        std::fs::write(&handle.path, data)
            .map(|_| data.len())
            .map_err(|e| e.to_string())
    }

    fn close(&self, _handle: Self::Handle) -> Result<(), String> {
        Ok(())
    }
    fn create_dir(&self, path: &str) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| e.to_string())
    }
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
    fn delete(&self, path: &str) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|e| e.to_string())
    }
}

// ============================================================
// WindowManager stub
// ============================================================

#[derive(Default)]
pub struct WindowManagerStub {
    windows: Vec<WindowHandle>,
}

impl WindowManager for WindowManagerStub {
    type Window = WindowHandle;

    fn create_window(
        &mut self,
        _title: &str,
        _width: u32,
        _height: u32,
    ) -> Result<Self::Window, String> {
        self.windows.push(WindowHandle);
        Ok(WindowHandle)
    }
    fn show(&self, _window: &Self::Window) {}
    fn hide(&self, _window: &Self::Window) {}
    fn process_events(&mut self) -> Vec<WindowEvent> {
        Vec::new()
    }
    fn get_client_size(&self, _window: &Self::Window) -> Result<(u32, u32), String> {
        Ok((800, 600))
    }
    fn destroy_window(&mut self, _window: Self::Window) {
        self.windows.clear();
    }
    fn set_title(&self, _window: &Self::Window, _title: &str) {}
}

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
        handle
            .0
            .join()
            .map_err(|e| format!("Thread panic: {:?}", e))
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

// ============================================================
// Common Windows-internal extern shims
// ============================================================

/// Initializes the security cookie used by /GS buffer-overflow protection.
///
/// The original Windows call triggers stack-canary setup.  In the stub we do
/// nothing — translated code rarely depends on the cookie value itself during
/// the DllMain / entry path.
#[allow(unused_variables)]
extern "system" fn __security_init_cookie() {
    // Stub: no-op placeholder for /GS security cookie initialization
}

/// Windows API equivalent for zeroing the security cookie at process shutdown.
#[allow(unused_variables)]
extern "system" fn __security_check_cookie(addr: *const core::ffi::c_void) {
    // Stub: no-op placeholder for /GS stack cookie validation
}

/// Dispatches DLL_PROCESS_ATTACH / DETACH / THREAD_ATTACH / DETACH to the
/// application's DllMain-style handler.
///
/// The original function lives inside the DLL itself, so we provide a no-op
/// stub that simply returns.  Real behavioral testing of the dispatch logic
/// requires the original binary FFI.
#[allow(unused_variables)]
extern "system" fn dllmain_dispatch(
    hinst: *mut core::ffi::c_void,
    fdw_reason: u32,
    reserved: *mut core::ffi::c_void,
) {
    // Stub: no-op placeholder for the DLL's internal DllMain dispatcher
}

/// Used by MSVC /GS to report a buffer-overflow detected at runtime.
///
/// The stub panics so that if translated code actually triggers this path the
/// failure is obvious rather than silently producing wrong results.
#[allow(unreachable_code)]
extern "system" fn __report_gsfailure(_reason: u32) -> ! {
    panic!("__report_gsfailure stub reached — this should not happen in translated code")
}

/// CRT heap allocation entry-point used by MSVC-compiled binaries.
#[allow(unused_variables)]
extern "system" fn _malloc_dbg(
    size: usize,
    _block_type: i32,
    _file: *const i8,
    _line: i32,
) -> *mut core::ffi::c_void {
    // Stub: falls back to std::alloc for unmanaged allocations
    unsafe {
        std::alloc::alloc(std::alloc::Layout::from_size_align(size, 8).unwrap())
            .cast::<core::ffi::c_void>()
    }
}

/// CRT heap free entry-point used by MSVC-compiled binaries.
#[allow(unused_variables)]
extern "system" fn _free_dbg(_ptr: *mut core::ffi::c_void, _block_type: i32) {
    // Stub: falls back to std::alloc for unmanaged deallocations
    if !_ptr.is_null() {
        unsafe {
            std::alloc::dealloc(
                _ptr.cast(),
                std::alloc::Layout::from_size_align(8, 8).unwrap(),
            );
        }
    }
}
