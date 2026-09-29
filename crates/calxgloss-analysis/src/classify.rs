//! DLL classification heuristics.
//!
//! This module provides lookup tables and classification logic for determining
//! the reverse-engineering strategy for a given DLL. Classification is based
//! on the DLL filename matching against known categories:
//!
//! - **Windows OS DLLs** — mapped via PAL to std/winit/etc.
//! - **Microsoft SDK DLLs** — replaced with Rust crates (e.g., d3d9 → wgpu)
//! - **Known third-party DLLs** — replaced with Rust crates (e.g., fmod → fmod-rs)
//! - **Everything else** — treated as project-specific or unknown, flagged for reverse engineering

use std::collections::HashSet;

use calxgloss_types::{DllCategory, Import};

/// Known Windows OS DLLs that should use PAL mapping.
///
/// These are core system DLLs that map to the Rust standard library, winit,
/// or other system-level crates. The strategy is `PalMapping`.
const WINDOWS_OS_DLLS: &[&str] = &[
    // Core Windows
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "comdlg32.dll",
    "shellwav.dll",
    "msvcrt.dll",
    "api-ms-win-core",
    "api-ms-win-base",
    "ext-ms-win",
    // Additional Windows system DLLs
    "ws2_32.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    "netapi32.dll",
    "sxs.dll",
    "cfgmgr32.dll",
    "setupapi.dll",
    "cmcfg32.dll",
    "crypt32.dll",
    "msimg32.dll",
    "imm32.dll",
    "msctf.dll",
    "dbghelp.dll",
    "profapi.dll",
    "winmm.dll",
    "version.dll",
    "powrprof.dll",
    "umpdc.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "shlwapi.dll",
    "mswsock.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "samlib.dll",
    "userenv.dll",
    "winspool.drv",
    "clbcatq.dll",
    "imagehlp.dll",
    "psapi.dll",
    "cryptbase.dll",
    "sal32.dll",
    "traceeventapi.dll",
    "thumbcache.dll",
    "uxtheme.dll",
    "dcomp.dll",
    "d3d10warp.dll",
    "dxgi.dll",
    "twinapi.appcore.dll",
    "windows.storage.dll",
    "windows.data.dll",
    "windows.graphics.dll",
    "windows.ui.dll",
    "wldp.dll",
    "bcryptprimitives.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "vcruntime140_atomic_wait.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll",
    "msvcp_win.dll",
    "msvcp90.dll",
    "msvcr100.dll",
    "msvcr110.dll",
    "msvcr120.dll",
    "concrt140.dll",
    "api-ms-win-crt",
    "ext-ms-win-crt",
];

/// Known Microsoft SDK DLLs that have Rust crate equivalents.
///
/// Maps from lowercase DLL name to the recommended Rust crate name.
/// The strategy is `CrateReplacement` with the specified crate.
const MICROSOFT_SDK_DLLS: &[(&str, &str)] = &[
    // DirectX 9
    ("d3d9.dll", "wgpu"),
    // DirectX 10/11/12
    ("d3d10.dll", "wgpu"),
    ("d3d10_1.dll", "wgpu"),
    ("d3d10level9.dll", "wgpu"),
    ("d3d11.dll", "wgpu"),
    ("d3d12.dll", "wgpu"),
    // DXGI
    ("dxgi.dll", "wgpu"),
    // Direct2D / DirectWrite
    ("d2d1.dll", "tiny-skia"),
    ("dwrite.dll", "skrifa"),
    // Other Microsoft SDK
    ("d3dcompiler_47.dll", "wgpu"),
    ("dxva2.dll", "wgpu"),
    ("mf.dll", "wgpu"),
    ("mfplat.dll", "wgpu"),
    ("mfplay.dll", "wgpu"),
    ("mpcdec.dll", "hound"),
];

/// Known third-party DLLs that have Rust crate equivalents.
///
/// Maps from lowercase DLL name to the recommended Rust crate name.
/// The strategy is `CrateReplacement` with the specified crate.
const KNOWN_THIRD_PARTY_DLLS: &[(&str, &str)] = &[
    // Audio
    ("fmod.dll", "fmod-rs"),
    ("fmodL.dll", "fmod-rs"),
    ("openal32.dll", "cpal"),
    ("openal.dll", "cpal"),
    ("xaudio2_9.dll", "cpal"),
    ("x3daudio1_7.dll", "cpal"),
    ("dsound.dll", "cpal"),
    // Physics
    ("bullet.dll", "rapier"),
    ("chipmunk.dll", "chipmunk2d-rs"),
    ("physx_64.dll", "nphysics"),
    ("ode.dll", "parry"),
    // Game engines / frameworks
    ("qt5core.dll", "iced"),
    ("qt5gui.dll", "iced"),
    ("qt5widgets.dll", "iced"),
    ("qt5qml.dll", "slint"),
    ("cairo.dll", "cairo-rs"),
    ("gdk-3.0.dll", "gtk3"),
    ("gtk-3.0.dll", "gtk3"),
    // Compression
    ("zlib1.dll", "flate2"),
    ("lzma.dll", "lzma-rs"),
    ("bz2.dll", "bzip2"),
    ("liblz4.dll", "lz4"),
    ("libzstd.dll", "zstd"),
    ("snappy.dll", "snap"),
    ("lz4.dll", "lz4"),
    ("xxhash.dll", "xxhash-rust"),
    // Scripting — V8 JavaScript engine
    ("v8.dll", "v8"),
    ("v8_libbase.dll", "v8"),
    ("v8_libplatform.dll", "v8"),
    ("v8_zlib.dll", "v8"),
    // Scripting
    ("lua51.dll", "mlua"),
    ("lua5.1.dll", "mlua"),
    ("lua5.1.dll", "mlua"),
    ("python3.dll", "pyo3"),
    ("python39.dll", "pyo3"),
    ("python38.dll", "pyo3"),
    ("python37.dll", "pyo3"),
    ("python310.dll", "pyo3"),
    ("python311.dll", "pyo3"),
    ("python312.dll", "pyo3"),
    // UI / Graphics
    ("skia.dll", "skia-safe"),
    ("harfbuzz.dll", "harfbuzz-rs"),
    ("freetype6.dll", "freetype"),
    ("libpng16.dll", "png"),
    ("libtiff.dll", "tiff"),
    ("libjpeg.dll", "jpeg"),
    ("libwebp.dll", "webp"),
    // Other utilities
    ("ws2_32.dll", "tokio"),
    ("winhttp.dll", "reqwest"),
    ("psapi.dll", "psutil"),
    ("dbghelp.dll", "pdb-parser"),
    ("miniz.dll", "miniz_oxide"),
    // Gaming / platform
    ("steam_api64.dll", "steamworks"),
    // Node.js / Electron
    ("node.dll", "nodejs-ffi"),
    ("libnode.dll", "nodejs-ffi"),
    ("libuv.dll", "uv"),
    // VB6 Runtime
    ("msvbvm60.dll", "vb6runtime"),
    ("msvbvm50.dll", "vb6runtime"),
];

/// Returns `true` if the DLL is a known Windows OS DLL.
pub fn is_windows_os_dll(dll_name: &str) -> bool {
    let lower = dll_name.to_lowercase();
    WINDOWS_OS_DLLS.iter().any(|known| {
        lower == known.to_lowercase() || lower.starts_with(known.to_lowercase().as_str())
    })
}

/// Returns the recommended Rust crate for a known Microsoft SDK DLL, or `None`.
pub fn microsoft_sdk_crate(dll_name: &str) -> Option<&'static str> {
    let lower = dll_name.to_lowercase();
    MICROSOFT_SDK_DLLS.iter().find_map(|(name, crate_name)| {
        if lower == name.to_lowercase() {
            Some(*crate_name)
        } else {
            None
        }
    })
}

/// Returns the recommended Rust crate for a known third-party DLL, or `None`.
pub fn known_third_party_crate(dll_name: &str) -> Option<&'static str> {
    let lower = dll_name.to_lowercase();
    KNOWN_THIRD_PARTY_DLLS
        .iter()
        .find_map(|(name, crate_name)| {
            if lower == name.to_lowercase() {
                Some(*crate_name)
            } else {
                None
            }
        })
}

/// Returns the lowercase DLL filename without the `.dll` extension.
///
/// Returns `None` if the name is empty or doesn't end with `.dll`.
pub fn dll_base_name(dll_name: &str) -> Option<String> {
    let lower = dll_name.trim().to_lowercase();
    if lower.is_empty() {
        return None;
    }
    lower.strip_suffix(".dll").map(|s| s.to_string())
}

/// Classifies a single DLL by filename, returning its category and strategy.
///
/// The classification follows this priority:
/// 1. Check against known third-party DLLs → `KnownThirdParty`
/// 2. Check against Microsoft SDK DLLs → `MicrosoftSdk`
/// 3. Check against Windows OS DLLs → `WindowsOs`
/// 4. Default → `ProjectSpecific` (assumed to be application-specific code)
///
/// # Example
///
/// ```
/// use calxgloss_analysis::classify_dll_name;
/// use calxgloss_types::DllCategory;
///
/// assert_eq!(classify_dll_name("kernel32.dll"), DllCategory::WindowsOs);
/// assert_eq!(classify_dll_name("d3d9.dll"), DllCategory::MicrosoftSdk);
/// assert_eq!(classify_dll_name("fmod.dll"), DllCategory::KnownThirdParty);
/// assert_eq!(classify_dll_name("my_game_logic.dll"), DllCategory::ProjectSpecific);
/// ```
pub fn classify_dll_name(dll_name: &str) -> DllCategory {
    // Check known third-party first (more specific)
    if known_third_party_crate(dll_name).is_some() {
        return DllCategory::KnownThirdParty;
    }

    // Check Microsoft SDK
    if microsoft_sdk_crate(dll_name).is_some() {
        return DllCategory::MicrosoftSdk;
    }

    // Check Windows OS
    if is_windows_os_dll(dll_name) {
        return DllCategory::WindowsOs;
    }

    // Default: assume project-specific
    DllCategory::ProjectSpecific
}

/// Returns the crate replacement name for a classified DLL.
///
/// Returns `Some(crate_name)` if the DLL is known to have a Rust crate equivalent,
/// or `None` if the DLL should be reverse-engineered.
pub fn crate_replacement_for(dll_name: &str, category: &DllCategory) -> Option<String> {
    match category {
        DllCategory::KnownThirdParty => known_third_party_crate(dll_name).map(|s| s.to_string()),
        DllCategory::MicrosoftSdk => microsoft_sdk_crate(dll_name).map(|s| s.to_string()),
        _ => None,
    }
}

/// Given a list of imports, returns the set of unique DLL names that are imported.
///
/// This is useful for determining what external dependencies a target binary has,
/// which informs the overall classification strategy.
pub fn imported_dll_names(imports: &[Import]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for import in imports {
        let dll = import.dll.trim().to_lowercase();
        if !dll.is_empty() && seen.insert(dll.clone()) {
            result.push(dll);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_os_dll_kernel32() {
        assert!(is_windows_os_dll("kernel32.dll"));
        assert!(is_windows_os_dll("KERNEL32.DLL"));
        assert!(is_windows_os_dll("User32.dll"));
        assert!(is_windows_os_dll("gdi32.dll"));
        assert!(is_windows_os_dll("advapi32.dll"));
        assert!(is_windows_os_dll("shell32.dll"));
    }

    #[test]
    fn test_windows_os_dll_api_minimization() {
        assert!(is_windows_os_dll("api-ms-win-core-path-l1-1-0.dll"));
        assert!(is_windows_os_dll("ext-ms-win-kernel32-l1-1-0.dll"));
    }

    #[test]
    fn test_not_windows_os_dll() {
        assert!(!is_windows_os_dll("my_app.dll"));
        assert!(!is_windows_os_dll("game_logic.dll"));
        assert!(!is_windows_os_dll(""));
    }

    #[test]
    fn test_microsoft_sdk_d3d9() {
        assert_eq!(microsoft_sdk_crate("d3d9.dll"), Some("wgpu"));
        assert_eq!(microsoft_sdk_crate("d3d11.dll"), Some("wgpu"));
        assert_eq!(microsoft_sdk_crate("d3d12.dll"), Some("wgpu"));
        assert_eq!(microsoft_sdk_crate("d2d1.dll"), Some("tiny-skia"));
        assert_eq!(microsoft_sdk_crate("dwrite.dll"), Some("skrifa"));
        assert_eq!(microsoft_sdk_crate("dxgi.dll"), Some("wgpu"));
    }

    #[test]
    fn test_microsoft_sdk_not_found() {
        assert_eq!(microsoft_sdk_crate("kernel32.dll"), None);
        assert_eq!(microsoft_sdk_crate("my_lib.dll"), None);
    }

    #[test]
    fn test_known_third_party_fmod() {
        assert_eq!(known_third_party_crate("fmod.dll"), Some("fmod-rs"));
        assert_eq!(known_third_party_crate("openal32.dll"), Some("cpal"));
        assert_eq!(known_third_party_crate("lua51.dll"), Some("mlua"));
        assert_eq!(known_third_party_crate("python312.dll"), Some("pyo3"));
        assert_eq!(known_third_party_crate("zlib1.dll"), Some("flate2"));
        assert_eq!(known_third_party_crate("msvbvm60.dll"), Some("vb6runtime"));
    }

    #[test]
    fn test_known_third_party_not_found() {
        assert_eq!(known_third_party_crate("kernel32.dll"), None);
        assert_eq!(known_third_party_crate("my_game.dll"), None);
    }

    #[test]
    fn test_classify_dll_name_windows_os() {
        assert_eq!(classify_dll_name("kernel32.dll"), DllCategory::WindowsOs);
        assert_eq!(classify_dll_name("user32.dll"), DllCategory::WindowsOs);
        assert_eq!(classify_dll_name("gdi32.dll"), DllCategory::WindowsOs);
    }

    #[test]
    fn test_classify_dll_name_microsoft_sdk() {
        assert_eq!(classify_dll_name("d3d9.dll"), DllCategory::MicrosoftSdk);
        assert_eq!(classify_dll_name("d3d11.dll"), DllCategory::MicrosoftSdk);
        assert_eq!(classify_dll_name("d2d1.dll"), DllCategory::MicrosoftSdk);
    }

    #[test]
    fn test_classify_dll_name_known_third_party() {
        assert_eq!(classify_dll_name("fmod.dll"), DllCategory::KnownThirdParty);
        assert_eq!(
            classify_dll_name("openal32.dll"),
            DllCategory::KnownThirdParty
        );
        assert_eq!(classify_dll_name("lua51.dll"), DllCategory::KnownThirdParty);
        assert_eq!(
            classify_dll_name("msvbvm60.dll"),
            DllCategory::KnownThirdParty
        );
    }

    #[test]
    fn test_classify_dll_name_project_specific() {
        assert_eq!(
            classify_dll_name("my_app.dll"),
            DllCategory::ProjectSpecific
        );
        assert_eq!(
            classify_dll_name("game_logic.dll"),
            DllCategory::ProjectSpecific
        );
        assert_eq!(
            classify_dll_name("renderer.dll"),
            DllCategory::ProjectSpecific
        );
    }

    #[test]
    fn test_crate_replacement_for_known_third_party() {
        assert_eq!(
            crate_replacement_for("fmod.dll", &DllCategory::KnownThirdParty),
            Some("fmod-rs".to_string())
        );
    }

    #[test]
    fn test_crate_replacement_for_microsoft_sdk() {
        assert_eq!(
            crate_replacement_for("d3d9.dll", &DllCategory::MicrosoftSdk),
            Some("wgpu".to_string())
        );
    }

    #[test]
    fn test_crate_replacement_for_windows_os() {
        assert_eq!(
            crate_replacement_for("kernel32.dll", &DllCategory::WindowsOs),
            None
        );
    }

    #[test]
    fn test_crate_replacement_for_project_specific() {
        assert_eq!(
            crate_replacement_for("my_app.dll", &DllCategory::ProjectSpecific),
            None
        );
    }

    #[test]
    fn test_dll_base_name() {
        assert_eq!(
            dll_base_name("game_logic.dll"),
            Some("game_logic".to_string())
        );
        assert_eq!(dll_base_name("KERNEL32.DLL"), Some("kernel32".to_string()));
        assert_eq!(dll_base_name("not_a_dll"), None);
        assert_eq!(dll_base_name(""), None);
    }

    #[test]
    fn test_imported_dll_names() {
        let imports = vec![
            Import {
                dll: "kernel32.dll".to_string(),
                function: "CreateFileA".to_string(),
            },
            Import {
                dll: "user32.dll".to_string(),
                function: "MessageBoxA".to_string(),
            },
            Import {
                dll: "kernel32.dll".to_string(),
                function: "ReadFile".to_string(),
            },
        ];

        let names = imported_dll_names(&imports);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"kernel32.dll".to_string()));
        assert!(names.contains(&"user32.dll".to_string()));
    }

    #[test]
    fn test_imported_dll_names_empty() {
        let imports: Vec<Import> = vec![];
        assert!(imported_dll_names(&imports).is_empty());
    }

    #[test]
    fn test_imported_dll_names_deduplication() {
        let imports = vec![
            Import {
                dll: "advapi32.dll".to_string(),
                function: "RegOpenKeyExA".to_string(),
            },
            Import {
                dll: "ADVAPI32.DLL".to_string(),
                function: "RegQueryValueExA".to_string(),
            },
        ];

        let names = imported_dll_names(&imports);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "advapi32.dll");
    }
}
