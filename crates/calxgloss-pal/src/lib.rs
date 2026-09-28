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

mod data;

pub use data::{MAPPINGS, CATEGORY_INDEX};

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


/// Lazy-initialized category index for efficient `for_category` lookups.
///
/// Built once on first access, then reused. No per-call allocation or leak.
///
/// Defined in the `data` module.

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
        // The IndexMap is built once at first access from the static data::MAPPINGS.
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
        // SAFETY: MAPPINGS is a static array defined in the data module.
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
