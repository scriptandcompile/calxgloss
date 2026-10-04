//! Vtable detection.
//!
//! This module will provide `VtableDetector` with `detect_vtables()`,
//! scanning paged `list_data_items` output for vtable-shaped data objects —
//! `vftable`-named items preceded by `vftable_meta_ptr` entries (the MSVC
//! RTTI pattern), keyed by address since `vftable` names are not unique. It
//! resolves method pointers to names and addresses, tracks base-class
//! inheritance, and recognizes COM interfaces via the
//! QueryInterface/AddRef/Release pattern.
