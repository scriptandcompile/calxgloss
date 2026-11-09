// Shared PAL stubs for scratch verification projects.
//
// This crate is the single source of stub types, traits, and
// implementations used by all scratch verification projects.
// Each project adds a path dependency to this crate and imports
// everything via `use pal::*;`.
//
// Stub content lives in stub_content.rs beside this file — the one source,
// embedded into calxgloss-verify and written out by its scaffold.

// Stub content embedded from calxgloss-verify's src/pal/src/stub_content.rs.
include!("stub_content.rs");

