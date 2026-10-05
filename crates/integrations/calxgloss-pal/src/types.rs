//! The [`ApiMapping`] and [`ApiMappings`] — the core PAL lookup types.

use calxgloss_types::ApiCategory;

use crate::data::{CATEGORY_INDEX, MAPPINGS};

// ============================================================
// ApiMapping
// ============================================================

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

// ============================================================
// ApiMappings
// ============================================================

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
    /// the LLM prompt.
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
