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

    /// The API category this call belongs to.
    pub category: ApiCategory,

    /// The cross-platform Rust equivalent (e.g., `std::fs::File::open`, `wgpu::Instance [PAL placeholder]`).
    pub rust_equivalent: &'static str,

    /// Human-readable notes about the mapping (e.g., "PAL placeholder — not yet implemented").
    pub notes: &'static str,
}

impl ApiMapping {
    /// Creates an `ApiMapping` from owned strings.
    ///
    /// The function leaks each string, so the `&'static str` fields live for
    /// the rest of the process. Use this when a mapping comes from dynamic
    /// text, such as configuration. For mappings that are compiled in,
    /// prefer using `ApiMappings::default()`.
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
/// The analysis and translation crates use this as the lookup structure for
/// deciding how a Windows API call is replaced with a cross-platform Rust
/// equivalent.
///
/// # Default Mappings
///
/// The default table covers the MVP-relevant API categories. For example:
/// - Win32 Core → std lib (implemented equivalents; a few entries are PAL placeholders)
/// - GDI → tiny-skia (PAL placeholders)
/// - DirectX → wgpu (PAL placeholders)
///
/// # Thread Safety
///
/// The table is compiled-in static data, so `ApiMappings` is `Sync + Send`
/// and one value can be shared across threads.
#[derive(Debug, Clone)]
pub struct ApiMappings(&'static [ApiMapping]);

/// The methods below read through the category index defined in the `data`
/// module. That index is built once, on first access, and then reused, so
/// each lookup has no per-call allocation or leak.
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
        // Read through the category index: an IndexMap built once, on first
        // use, from the static data::MAPPINGS table. The lookup itself has
        // no per-call allocation or leak.
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

    /// Returns the API mappings for the given categories, grouped by category.
    ///
    /// The translation pipeline uses this for the LLM prompt: for each API
    /// category a function touches, it adds every mapping-table row for that
    /// category.
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

impl ApiMappings {
    /// Builds a table from mappings the caller provides (issue #323).
    ///
    /// An `ApiMapping` field is `&'static str` because the default table is
    /// compiled in. So this function leaks the owned strings behind
    /// `mappings` into a leaked boxed slice — the same convention
    /// [`ApiMapping::new`] already applies to its own string fields. A custom
    /// table is built at startup or once per agent session, not per call, so
    /// the one leak per table stays bounded.
    ///
    /// The custom table answers every read that goes through the instance:
    /// `lookup`, `iter`, and the analyzer's API tagging. Known limitation:
    /// [`for_category`](Self::for_category) — and `for_categories` through
    /// it — always reads the static default data, whichever instance it is
    /// called on, so the prompt's category-grouped mapping rows still come
    /// from the default table.
    pub fn from_custom(mappings: Vec<ApiMapping>) -> Self {
        ApiMappings(Box::leak(mappings.into_boxed_slice()))
    }
}

/// Returns the number of API mappings in the default table.
///
/// This is useful for tests and diagnostics.
pub fn mapping_count() -> usize {
    ApiMappings::default().len()
}
