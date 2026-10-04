//! Core data types for the recovered type database.
//!
//! This module holds the serialized shape of everything the recovery engines
//! produce:
//!
//! - [`NamedType`], [`TypeKind`], [`StructField`]: named types pulled from
//!   Ghidra's Type Manager (struct, class, union, enum) with field layouts.
//! - `Vtable`, `VtableMethod`: detected vtables with resolved method pointers
//!   and base-class inheritance.
//! - `InferredStruct`, `InferredField`, `FieldType`: struct layouts inferred
//!   from string-literal clustering, with confidence scores.
//! - `TypeDatabase`, `ScanMetadata`: the persisted per-DLL database and its
//!   scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

use calxgloss_ghidra::{DataTypeEntry, EnumDefinition, StructLayout};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================
// Type kind
// ============================================================

/// The kind of a named type in Ghidra's Type Manager.
///
/// The bridge classifies every Type Manager entry as struct, union, enum,
/// typedef, pointer, array, function, or primitive. Ghidra models C++ classes
/// as structures, so a recovered class arrives as [`TypeKind::Struct`];
/// [`TypeKind::Class`] is reserved for kinds confirmed by other signals
/// (RTTI, vtable linkage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    /// A structure (or a C++ class, which Ghidra stores as a structure).
    Struct,
    /// A class confirmed by a signal beyond its structure layout.
    Class,
    /// A union. The bridge classifies unions but exposes no layout endpoint,
    /// so a recovered union carries its size but no fields.
    Union,
    /// An enumeration with named members.
    Enum,
    /// A typedef alias. The alias target is not reported by the endpoints
    /// the scan reads, so a typedef carries its size only.
    Typedef,
    /// Anything the scan could not classify into the kinds above (function
    /// signatures, primitives outside the builtin category).
    Other,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            TypeKind::Struct => "struct",
            TypeKind::Class => "class",
            TypeKind::Union => "union",
            TypeKind::Enum => "enum",
            TypeKind::Typedef => "typedef",
            TypeKind::Other => "other",
        };
        f.write_str(label)
    }
}

// ============================================================
// Layout members
// ============================================================

/// One field of a recovered structure layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name as Ghidra labels it; `(unnamed)` for anonymous fields.
    pub name: String,
    /// Byte offset of the field from the start of the structure.
    pub offset: u64,
    /// Size of the field in bytes.
    pub size: u64,
    /// The field's data type name, e.g. `dword` or `char[2]`.
    pub type_name: String,
}

/// One member of a recovered enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumMember {
    /// Member name, e.g. `ExceptionContinueExecution`.
    pub name: String,
    /// Member value; signed because Ghidra enums may hold negative values.
    pub value: i64,
}

// ============================================================
// Named types
// ============================================================

/// A named type recovered from Ghidra's Type Manager.
///
/// The Type Manager holds every type the program knows about, including types
/// never applied to a symbol, so a `NamedType` may describe a type that
/// appears nowhere in the listing. `path` is the Type Manager path and is
/// unique — type *names* are not, so the database keys by path.
///
/// A type whose layout probe missed or failed still appears, with `size`
/// taken from the listing and `fields`/`members` empty: a type known to exist
/// without its layout is worth keeping, and the kind records what the scan
/// could establish about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedType {
    /// The type name, e.g. `IMAGE_DOS_HEADER`. Pointer variants arrive as
    /// separate entries (`name *`) and are not recovered.
    pub name: String,
    /// The kind the scan established, or [`TypeKind::Other`] when it could
    /// not.
    pub kind: TypeKind,
    /// The Type Manager category the type sits in, e.g. `pe` or `excpt.h`.
    pub category: String,
    /// Full path through the Type Manager, e.g. `/pe/IMAGE_DOS_HEADER`.
    pub path: String,
    /// Size in bytes. `None` when Ghidra reports the size as `variable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Alignment in bytes, when a layout probe reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u64>,
    /// Structure fields, in offset order. Empty for kinds without a layout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<StructField>,
    /// Enumeration members. Empty for kinds without members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<EnumMember>,
}

impl NamedType {
    /// A type recorded from the listing alone, without a layout.
    ///
    /// This is the degraded shape: the scan knows the type exists, what
    /// category it sits in, and how large it is, but nothing of its internals.
    pub fn from_listing(entry: &DataTypeEntry, kind: TypeKind) -> Self {
        Self {
            name: entry.name.clone(),
            kind,
            category: entry.category.clone(),
            path: entry.path.clone(),
            size: entry.size,
            alignment: None,
            fields: Vec::new(),
            members: Vec::new(),
        }
    }

    /// A structure confirmed by a `get_struct_layout` response.
    ///
    /// The layout's size and alignment win over the listing's: the layout is
    /// the authoritative read of the same type, and the listing may have
    /// rendered the size as `variable`.
    pub fn from_struct(entry: &DataTypeEntry, layout: &StructLayout) -> Self {
        Self {
            name: entry.name.clone(),
            kind: TypeKind::Struct,
            category: entry.category.clone(),
            path: entry.path.clone(),
            size: Some(layout.size),
            alignment: Some(layout.alignment),
            fields: layout
                .fields
                .iter()
                .map(|f| StructField {
                    name: f.field_name.clone(),
                    offset: f.offset,
                    size: f.size,
                    type_name: f.type_name.clone(),
                })
                .collect(),
            members: Vec::new(),
        }
    }

    /// An enumeration confirmed by a `get_enum_values` response.
    pub fn from_enum(entry: &DataTypeEntry, definition: &EnumDefinition) -> Self {
        Self {
            name: entry.name.clone(),
            kind: TypeKind::Enum,
            category: entry.category.clone(),
            path: entry.path.clone(),
            size: Some(definition.size),
            alignment: None,
            fields: Vec::new(),
            members: definition
                .members
                .iter()
                .map(|m| EnumMember {
                    name: m.name.clone(),
                    value: m.value,
                })
                .collect(),
        }
    }

    /// Whether a layout or member list was recovered for this type.
    pub fn has_layout(&self) -> bool {
        !self.fields.is_empty() || !self.members.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, category: &str, size: Option<u64>) -> DataTypeEntry {
        DataTypeEntry {
            name: name.to_string(),
            category: category.to_string(),
            size,
            path: format!("/{category}/{name}"),
        }
    }

    #[test]
    fn named_type_serde_round_trips_every_kind() {
        let mut struct_type = NamedType::from_listing(
            &entry("IMAGE_DOS_HEADER", "pe", Some(128)),
            TypeKind::Struct,
        );
        struct_type.alignment = Some(1);
        struct_type.fields.push(StructField {
            name: "e_magic".into(),
            offset: 0,
            size: 2,
            type_name: "char[2]".into(),
        });
        let enum_type = NamedType {
            members: vec![EnumMember {
                name: "ExceptionContinueExecution".into(),
                value: 0,
            }],
            ..NamedType::from_listing(
                &entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
                TypeKind::Enum,
            )
        };

        let json = serde_json::to_string(&vec![struct_type, enum_type]).unwrap();
        // Kinds serialize snake_case, matching the workspace's serde convention.
        assert!(json.contains("\"kind\":\"struct\""));
        assert!(json.contains("\"kind\":\"enum\""));
        let back: Vec<NamedType> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].fields[0].name, "e_magic");
        assert_eq!(back[1].members[0].value, 0);
    }

    #[test]
    fn empty_layout_sections_are_not_serialized() {
        let typedef =
            NamedType::from_listing(&entry("HWND", "winuser.h", Some(4)), TypeKind::Typedef);
        let json = serde_json::to_string(&typedef).unwrap();
        assert!(!json.contains("\"fields\""));
        assert!(!json.contains("\"members\""));
        assert!(!json.contains("\"alignment\""));
    }

    #[test]
    fn from_struct_maps_the_layout_fields() {
        // The IMAGE_DOS_HEADER layout as `get_struct_layout` renders it.
        let layout = StructLayout {
            name: "IMAGE_DOS_HEADER".into(),
            size: 128,
            alignment: 1,
            fields: vec![
                calxgloss_ghidra::StructFieldLayout {
                    offset: 0,
                    size: 2,
                    type_name: "char[2]".into(),
                    field_name: "e_magic".into(),
                },
                calxgloss_ghidra::StructFieldLayout {
                    offset: 60,
                    size: 4,
                    type_name: "dword".into(),
                    field_name: "e_lfanew".into(),
                },
            ],
        };
        let recovered =
            NamedType::from_struct(&entry("IMAGE_DOS_HEADER", "pe", Some(128)), &layout);
        assert_eq!(recovered.kind, TypeKind::Struct);
        assert_eq!(recovered.size, Some(128));
        assert_eq!(recovered.alignment, Some(1));
        assert_eq!(recovered.fields.len(), 2);
        assert_eq!(recovered.fields[1].name, "e_lfanew");
        assert_eq!(recovered.fields[1].offset, 60);
        assert!(recovered.has_layout());
    }

    #[test]
    fn from_enum_maps_the_members() {
        let definition = EnumDefinition {
            name: "_EXCEPTION_DISPOSITION".into(),
            size: 4,
            members: vec![
                calxgloss_ghidra::EnumMember {
                    name: "ExceptionContinueExecution".into(),
                    value: 0,
                },
                calxgloss_ghidra::EnumMember {
                    name: "ExceptionContinueSearch".into(),
                    value: 1,
                },
            ],
        };
        let recovered = NamedType::from_enum(
            &entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
            &definition,
        );
        assert_eq!(recovered.kind, TypeKind::Enum);
        assert_eq!(recovered.members.len(), 2);
        assert_eq!(recovered.members[1].name, "ExceptionContinueSearch");
        assert_eq!(recovered.members[1].value, 1);
    }

    #[test]
    fn from_listing_keeps_the_size_and_carries_no_layout() {
        // The degraded shape: a type known to exist but not resolved.
        let recovered =
            NamedType::from_listing(&entry("SOME_THING", "unknown", None), TypeKind::Other);
        assert_eq!(recovered.size, None);
        assert!(recovered.fields.is_empty());
        assert!(!recovered.has_layout());
    }

    #[test]
    fn type_kind_displays_its_serde_label() {
        assert_eq!(TypeKind::Struct.to_string(), "struct");
        assert_eq!(TypeKind::Typedef.to_string(), "typedef");
        assert_eq!(TypeKind::Other.to_string(), "other");
    }
}
