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

mod data;
mod types;

#[cfg(test)]
mod tests;

pub use types::{ApiMapping, ApiMappings, mapping_count};
