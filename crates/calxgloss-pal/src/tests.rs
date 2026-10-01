use crate::types::{ApiMapping, ApiMappings, mapping_count};
use calxgloss_types::ApiCategory;

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
