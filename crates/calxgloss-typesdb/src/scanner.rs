//! Named type recovery from Ghidra's Type Manager.
//!
//! This module will provide `TypeLibraryScanner` with `scan_named_types()`,
//! querying the bridge's `list_data_types` / `get_struct_layout` /
//! `get_enum_values` endpoints and returning every named type in the Type
//! Manager — including types never applied to a symbol. Malformed or
//! partially available type data degrades gracefully rather than failing the
//! whole scan.
