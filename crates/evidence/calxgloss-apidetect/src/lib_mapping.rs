//! Library mapping database: known imports → library + Rust crate suggestion.
//!
//! A [`MappingDatabase`] maps import names to the library they belong to and
//! the Rust crate that replaces them. The builtin table covers the eight
//! libraries of the P9 scope (DirectX 9, SDL2, Win32, POSIX, PNG, zlib,
//! stdio, C++ STL); [`MappingDatabase::with_library`] adds or replaces a
//! whole library entry for custom binaries.
//!
//! Each entry also carries the enrichment the findings ride: a
//! [`category`](LibraryMapping::category) — a plain string aligned with the
//! PAL `ApiCategory` display names (Win32Core, DirectX, SDL2, POSIX, PNG,
//! zlib, stdio, C++ STL) so prompt consumers see one vocabulary without the
//! evidence crate depending on PAL — and the crate suggestion's optional
//! [`features`](LibraryMapping::features), rendered into the `crate[feat]`
//! form by the finding's suggestion accessor. A custom entry carries both
//! like the builtin table; an entry that names no category claims none.
//!
//! Matching is by exact name — both the raw (possibly mangled) spelling and
//! the demangled spelling are listed where they differ, because the import
//! table and call-graph edges may carry either.

use std::collections::HashMap;

/// One library's entry in the mapping database: the import names it owns
/// and the Rust crate that replaces them, with the category and feature
/// flags the identified findings carry.
#[derive(Debug, Clone)]
pub struct LibraryMapping {
    /// Library name (e.g. `"zlib"`, `"DirectX 9"`).
    pub library: String,
    /// Import names owned by this library.
    pub imports: Vec<String>,
    /// Rust crate suggestion (e.g. `"flate2"`, `"windows / std::fs"`).
    pub rust_crate: String,
    /// The API category the library's surface belongs to, spelled with the
    /// PAL `ApiCategory` display names (e.g. `"Win32Core"`, `"zlib"`);
    /// `None` when the entry claims no category.
    pub category: Option<String>,
    /// Feature flags the crate suggestion carries (e.g. `"png"` for
    /// `image`), rendered into the `crate[feat]` suggestion form; empty
    /// when the suggestion needs no features.
    pub features: Vec<String>,
}

/// What the database knows about one import name: the record an identified
/// finding is built from, with the library, crate suggestion, category, and
/// feature flags the entry carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedApi {
    /// The library the import belongs to (e.g. `"zlib"`).
    pub library: String,
    /// The Rust crate standing in for the import (e.g. `"flate2"`).
    pub rust_crate: String,
    /// The API category the entry names, when it names one.
    pub category: Option<String>,
    /// Feature flags the crate suggestion carries, empty when none.
    pub features: Vec<String>,
}

/// Lookup table from import name to library and Rust crate suggestion.
#[derive(Debug, Clone, Default)]
pub struct MappingDatabase {
    by_name: HashMap<String, MappedApi>,
}

impl MappingDatabase {
    /// An empty database (no libraries).
    pub fn new() -> Self {
        Self::default()
    }

    /// The builtin database covering the P9 scope's eight libraries.
    pub fn builtin() -> Self {
        let mut db = Self::new();
        for mapping in builtin_mappings() {
            db.add_library(mapping);
        }
        db
    }

    /// Add a library entry, replacing any previous entry for the same
    /// library name.
    pub fn with_library(mut self, mapping: LibraryMapping) -> Self {
        self.add_library(mapping);
        self
    }

    /// Add a library entry, replacing any previous entry for the same
    /// library name.
    pub fn add_library(&mut self, mapping: LibraryMapping) {
        // Drop the names of the previous entry for this library, if any.
        self.by_name
            .retain(|_, entry| entry.library != mapping.library);
        for name in mapping.imports {
            self.by_name.insert(
                name,
                MappedApi {
                    library: mapping.library.clone(),
                    rust_crate: mapping.rust_crate.clone(),
                    category: mapping.category.clone(),
                    features: mapping.features.clone(),
                },
            );
        }
    }

    /// Look up an import name: the [`MappedApi`] record — library, crate
    /// suggestion, category, and feature flags — when known.
    pub fn lookup(&self, name: &str) -> Option<MappedApi> {
        self.by_name.get(name).cloned()
    }

    /// The library names the table covers, sorted.
    pub fn libraries(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .by_name
            .values()
            .map(|entry| entry.library.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Number of import names in the table.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the table has no import names.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The builtin library mappings of [`MappingDatabase::builtin`].
///
/// Each entry names its category with the PAL `ApiCategory` display
/// spelling so prompt consumers see one vocabulary, and carries feature
/// flags where the suggested crate has one that fits the library's
/// surface (`image[png]`, `flate2[zlib]`); entries whose suggestion is
/// plain std carry none.
fn builtin_mappings() -> Vec<LibraryMapping> {
    vec![
        LibraryMapping {
            library: "DirectX 9".into(),
            imports: [
                "Direct3DCreate9",
                "D3DCompile",
                "D3DXCreateTextureFromFileA",
                "D3DXCreateTextureFromFileW",
                "DirectSoundCreate",
                "DirectSoundCreate8",
                "DirectInput8Create",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "wgpu / directx".into(),
            category: Some("DirectX".into()),
            features: Vec::new(),
        },
        LibraryMapping {
            library: "SDL2".into(),
            imports: [
                "SDL_Init",
                "SDL_CreateWindow",
                "SDL_CreateRenderer",
                "SDL_PollEvent",
                "SDL_Quit",
                "SDL_GetError",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "sdl2".into(),
            category: Some("SDL2".into()),
            features: Vec::new(),
        },
        LibraryMapping {
            library: "Win32".into(),
            imports: [
                "CreateFileA",
                "CreateFileW",
                "ReadFile",
                "WriteFile",
                "CloseHandle",
                "GetLastError",
                "VirtualAlloc",
                "VirtualFree",
                "LoadLibraryA",
                "LoadLibraryW",
                "GetProcAddress",
                "FreeLibrary",
                "MessageBoxA",
                "MessageBoxW",
                "OutputDebugStringA",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "windows / std::fs".into(),
            category: Some("Win32Core".into()),
            features: Vec::new(),
        },
        LibraryMapping {
            library: "POSIX".into(),
            imports: [
                "open", "read", "write", "close", "fopen", "fclose", "fread", "fwrite", "malloc",
                "calloc", "realloc", "free", "memcpy", "memset", "strlen", "strcmp", "strcpy",
                "strcat", "printf", "fprintf", "snprintf", "mmap", "munmap",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "std::fs / std::io".into(),
            category: Some("POSIX".into()),
            features: Vec::new(),
        },
        LibraryMapping {
            library: "PNG".into(),
            imports: [
                "png_create_read_struct",
                "png_create_write_struct",
                "png_destroy_read_struct",
                "png_destroy_write_struct",
                "png_init_io",
                "png_read_info",
                "png_read_image",
                "png_write_info",
                "png_write_image",
                "png_set_strip_16",
                "png_set_expand",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "image / png".into(),
            category: Some("PNG".into()),
            features: vec!["png".into()],
        },
        LibraryMapping {
            library: "zlib".into(),
            imports: [
                "deflate",
                "deflateInit_",
                "deflateInit2_",
                "deflateEnd",
                "inflate",
                "inflateInit_",
                "inflateInit2_",
                "inflateEnd",
                "compress",
                "compress2",
                "uncompress",
                "crc32",
                "adler32",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "flate2".into(),
            category: Some("zlib".into()),
            features: vec!["zlib".into()],
        },
        LibraryMapping {
            library: "stdio".into(),
            imports: [
                "puts", "putchar", "getchar", "scanf", "fscanf", "sscanf", "fgets", "fputs",
                "fseek", "ftell", "rewind", "remove", "rename",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "std::io".into(),
            category: Some("stdio".into()),
            features: Vec::new(),
        },
        LibraryMapping {
            library: "C++ STL".into(),
            imports: [
                // Raw (possibly decorated) spellings.
                "_Znwm",
                "_ZdlPv",
                "_Znaj",
                "_ZdaPv",
                "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c",
                "_ZSt9terminatev",
                "??2@YAPEAX_K@Z",
                "??3@YAXPEAX@Z",
                "?terminate@@YAXXZ",
                // Demangled spellings.
                "operator new",
                "operator delete",
                "operator new[]",
                "operator delete[]",
                "std::terminate",
                "std::ostream::operator<<",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            rust_crate: "std / Vec".into(),
            category: Some("C++ STL".into()),
            features: Vec::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(library: &str, name: &str) -> Option<MappedApi> {
        MappingDatabase::builtin()
            .lookup(name)
            .filter(|entry| entry.library == library)
    }

    #[test]
    fn builtin_libraries_lists_the_eight_covered_names() {
        assert_eq!(
            MappingDatabase::builtin().libraries(),
            vec![
                "C++ STL",
                "DirectX 9",
                "PNG",
                "POSIX",
                "SDL2",
                "Win32",
                "stdio",
                "zlib",
            ]
        );
    }

    #[test]
    fn builtin_libraries_report_their_categories() {
        let db = MappingDatabase::builtin();
        let categories: [(&str, Option<&str>); 8] = [
            ("Direct3DCreate9", Some("DirectX")),
            ("SDL_Init", Some("SDL2")),
            ("CreateFileA", Some("Win32Core")),
            ("open", Some("POSIX")),
            ("png_read_info", Some("PNG")),
            ("inflate", Some("zlib")),
            ("puts", Some("stdio")),
            ("_Znwm", Some("C++ STL")),
        ];
        for (name, expected) in categories {
            let entry = db.lookup(name).expect("the builtin table knows the name");
            assert_eq!(entry.category.as_deref(), expected, "category of {name}");
        }
    }

    #[test]
    fn builtin_maps_directx9_imports() {
        let entry = lookup("DirectX 9", "Direct3DCreate9").unwrap();
        assert_eq!(entry.library, "DirectX 9");
        assert_eq!(entry.rust_crate, "wgpu / directx");
        assert_eq!(entry.category.as_deref(), Some("DirectX"));
        assert!(lookup("DirectX 9", "D3DCompile").is_some());
    }

    #[test]
    fn builtin_maps_sdl2_imports() {
        let entry = lookup("SDL2", "SDL_Init").unwrap();
        assert_eq!(entry.library, "SDL2");
        assert_eq!(entry.rust_crate, "sdl2");
        assert_eq!(entry.category.as_deref(), Some("SDL2"));
        assert!(lookup("SDL2", "SDL_CreateWindow").is_some());
    }

    #[test]
    fn builtin_maps_win32_imports() {
        let entry = lookup("Win32", "CreateFileA").unwrap();
        assert_eq!(entry.library, "Win32");
        assert_eq!(entry.rust_crate, "windows / std::fs");
        assert_eq!(entry.category.as_deref(), Some("Win32Core"));
        assert!(lookup("Win32", "VirtualAlloc").is_some());
        assert!(lookup("Win32", "GetProcAddress").is_some());
    }

    #[test]
    fn builtin_maps_posix_imports() {
        let entry = lookup("POSIX", "open").unwrap();
        assert_eq!(entry.library, "POSIX");
        assert_eq!(entry.rust_crate, "std::fs / std::io");
        assert_eq!(entry.category.as_deref(), Some("POSIX"));
        assert!(lookup("POSIX", "malloc").is_some());
        assert!(lookup("POSIX", "memcpy").is_some());
    }

    #[test]
    fn builtin_maps_png_imports_with_the_png_feature() {
        let entry = lookup("PNG", "png_read_info").unwrap();
        assert_eq!(entry.library, "PNG");
        assert_eq!(entry.rust_crate, "image / png");
        assert_eq!(entry.category.as_deref(), Some("PNG"));
        assert_eq!(entry.features, vec!["png".to_string()]);
        assert!(lookup("PNG", "png_create_read_struct").is_some());
    }

    #[test]
    fn builtin_maps_zlib_imports_with_the_zlib_feature() {
        let entry = lookup("zlib", "inflate").unwrap();
        assert_eq!(entry.library, "zlib");
        assert_eq!(entry.rust_crate, "flate2");
        assert_eq!(entry.category.as_deref(), Some("zlib"));
        assert_eq!(entry.features, vec!["zlib".to_string()]);
        assert!(lookup("zlib", "deflateInit_").is_some());
        assert!(lookup("zlib", "crc32").is_some());
    }

    #[test]
    fn builtin_maps_stdio_imports() {
        let entry = lookup("stdio", "puts").unwrap();
        assert_eq!(entry.library, "stdio");
        assert_eq!(entry.rust_crate, "std::io");
        assert_eq!(entry.category.as_deref(), Some("stdio"));
        assert!(lookup("stdio", "fgets").is_some());
    }

    #[test]
    fn builtin_maps_cpp_stl_imports() {
        let entry = lookup("C++ STL", "_Znwm").unwrap();
        assert_eq!(entry.library, "C++ STL");
        assert_eq!(entry.rust_crate, "std / Vec");
        assert_eq!(entry.category.as_deref(), Some("C++ STL"));
        // Both mangled and demangled spellings resolve.
        assert!(lookup("C++ STL", "operator new").is_some());
        assert!(lookup("C++ STL", "??2@YAPEAX_K@Z").is_some());
    }

    #[test]
    fn builtin_leaves_unknown_names_unmapped() {
        assert!(
            MappingDatabase::builtin()
                .lookup("SomeVendorFunction")
                .is_none()
        );
    }

    #[test]
    fn with_library_adds_a_custom_entry() {
        let db = MappingDatabase::builtin().with_library(LibraryMapping {
            library: "CustomEngine".into(),
            imports: vec!["Engine_LoadAsset".into()],
            rust_crate: "custom_engine".into(),
            category: Some("SDL2".into()),
            features: vec!["bundled".into()],
        });
        let entry = db.lookup("Engine_LoadAsset").unwrap();
        assert_eq!(entry.library, "CustomEngine");
        assert_eq!(entry.rust_crate, "custom_engine");
        assert_eq!(entry.category.as_deref(), Some("SDL2"));
        assert_eq!(entry.features, vec!["bundled".to_string()]);
    }

    #[test]
    fn with_library_replaces_the_previous_entry_for_a_library() {
        let db = MappingDatabase::builtin().with_library(LibraryMapping {
            library: "zlib".into(),
            imports: vec!["my_inflate".into()],
            rust_crate: "my_zlib".into(),
            category: Some("zlib".into()),
            features: vec!["deflate".into()],
        });
        assert!(db.lookup("inflate").is_none());
        let entry = db.lookup("my_inflate").unwrap();
        assert_eq!(entry.library, "zlib");
        assert_eq!(entry.rust_crate, "my_zlib");
        assert_eq!(entry.category.as_deref(), Some("zlib"));
        assert_eq!(entry.features, vec!["deflate".to_string()]);
    }
}
