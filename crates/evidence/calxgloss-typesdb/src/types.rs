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
//! All types derive `Serialize`/`Deserialize`. Ghidra wire records convert into
//! recovered records via `From<&StructFieldLayout>` and `From<&calxgloss_ghidra::EnumMember>`
//! — the wire and persisted shapes stay deliberately split, and these impls are
//! the only mapping between them. Recovered records also convert into prompt
//! data: `From<&NamedType>` and `From<&InferredStruct>` render a
//! [`calxgloss_prompts::StructuredData`] for the translation prompts.

use calxgloss_ghidra::{DataTypeEntry, EnumDefinition, StructFieldLayout, StructLayout};
use calxgloss_prompts::StructuredData;
use serde::{Deserialize, Serialize};
use std::fmt;

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence` the
// shared 0–100 evidence score; both live in `calxgloss-types` so every engine
// crate keys its artifacts and scores the same way. Re-exported here so
// `calxgloss_typesdb::types::*` keeps resolving for existing callers.
pub use calxgloss_types::{Confidence, ScanMetadata};

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

calxgloss_types::display_serde_label!(TypeKind {
    Struct => "struct",
    Class => "class",
    Union => "union",
    Enum => "enum",
    Typedef => "typedef",
    Other => "other",
});

// ============================================================
// Layout members
// ============================================================

/// One field of a recovered structure layout.
///
/// The persisted counterpart of the wire shape `calxgloss_ghidra::StructFieldLayout`.
/// The two stay deliberately split — that one is the parsed `/get_struct_layout`
/// response owned by the HTTP client, this one the serde'd recovered record —
/// and [`From<&StructFieldLayout>`] is the only mapping between them.
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
///
/// The persisted counterpart of the wire shape `calxgloss_ghidra::EnumMember`.
/// The two records are identical today but stay split on purpose, for the same
/// reason as [`StructField`], and [`From<&calxgloss_ghidra::EnumMember>`] is
/// the only mapping between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumMember {
    /// Member name, e.g. `ExceptionContinueExecution`.
    pub name: String,
    /// Member value; signed because Ghidra enums may hold negative values.
    pub value: i64,
}

/// Wire → recovered conversions for the layout leaves.
///
/// These impls are the single place the Ghidra wire shapes and the persisted
/// recovered shapes meet; keeping the field copies here rather than inline in
/// [`NamedType::from_struct`] / [`NamedType::from_enum`] means a wire-shape
/// change breaks exactly one compile.
impl From<&StructFieldLayout> for StructField {
    fn from(field: &StructFieldLayout) -> Self {
        Self {
            name: field.field_name.clone(),
            offset: field.offset,
            size: field.size,
            type_name: field.type_name.clone(),
        }
    }
}

impl From<&calxgloss_ghidra::EnumMember> for EnumMember {
    fn from(member: &calxgloss_ghidra::EnumMember) -> Self {
        Self {
            name: member.name.clone(),
            value: member.value,
        }
    }
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
            fields: layout.fields.iter().map(StructField::from).collect(),
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
            members: definition.members.iter().map(EnumMember::from).collect(),
        }
    }

    /// Whether a layout or member list was recovered for this type.
    pub fn has_layout(&self) -> bool {
        !self.fields.is_empty() || !self.members.is_empty()
    }
}

// ============================================================
// Vtables
// ============================================================

/// One resolved entry of a detected vtable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableMethod {
    /// Slot index within the table, starting at 0.
    pub slot: usize,
    /// The address the slot's pointer points at.
    pub address: u64,
    /// The function Ghidra has at that address. `None` when the pointer lands
    /// outside any known function body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A vtable recovered from the program's defined data.
///
/// Ghidra names every MSVC vtable `vftable`, so the label identifies nothing
/// on its own and the database keys by address. A vtable paired with the
/// `vftable_meta_ptr` entry that precedes it is confirmed by the RTTI pattern,
/// and its class name and base classes are recovered by following the RTTI
/// chain; an unpaired one is still a vtable, just without the RTTI record to
/// read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtable {
    /// Address of the table itself.
    pub address: u64,
    /// The label Ghidra shows, e.g. `vftable`.
    pub label: String,
    /// Size of the table in bytes.
    pub size: u64,
    /// The address of the paired `vftable_meta_ptr` entry, when one precedes
    /// the table — the RTTI confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_ptr_address: Option<u64>,
    /// Method slots, in table order. Empty when the table's contents could not
    /// be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<VtableMethod>,
    /// The owning class, demangled from the RTTI TypeDescriptor
    /// (`.?AVWidget@@` → `Widget`), when the chain resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// Base classes from the RTTI ClassHierarchyDescriptor, in descriptor
    /// order. Empty for a root class or an unresolved chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_classes: Vec<String>,
    /// Whether the leading slots spell the COM `IUnknown` prefix
    /// (QueryInterface / AddRef / Release).
    #[serde(default)]
    pub is_com_interface: bool,
}

impl Vtable {
    /// Whether the table carried the `vftable_meta_ptr` RTTI confirmation.
    pub fn is_confirmed(&self) -> bool {
        self.meta_ptr_address.is_some()
    }
}

// ============================================================
// Inferred structs
// ============================================================

/// The kind inferred for one string-inferred field.
///
/// The kind comes from the *shape* of the literal that named the field —
/// `width=100` suggests an integer, `ratio=0.5` a float, `enabled=true` a
/// flag, a bare identifier text — so it is a suggestion for the translator
/// rather than a fact read out of the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// Text, reached through a pointer.
    String,
    /// An integer of unspecified width.
    Integer,
    /// A floating-point value.
    Float,
    /// A boolean flag.
    Boolean,
    /// Anything the inference could not classify.
    Unknown,
}

impl FieldType {
    /// The C declaration a field of this kind suggests.
    pub fn c_type(&self) -> &'static str {
        match self {
            FieldType::String => "char *",
            FieldType::Integer => "int",
            FieldType::Float => "float",
            FieldType::Boolean => "bool",
            FieldType::Unknown => "undefined",
        }
    }

    /// The size a field of this kind occupies, in bytes. `None` for a kind
    /// with no size of its own; text is reached through a pointer, so it
    /// takes the program's pointer size.
    pub fn suggested_size(&self, pointer_size: u64) -> Option<u64> {
        match self {
            FieldType::String => Some(pointer_size),
            FieldType::Integer | FieldType::Float => Some(4),
            FieldType::Boolean => Some(1),
            FieldType::Unknown => None,
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.c_type())
    }
}

/// How an inferred struct's name was derived.
///
/// The name is part of the evidence report: a candidate named from the data
/// it came from is a better hypothesis than one named after its own address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOrigin {
    /// The literals share a qualifier: `player.x`, `player.y` → `Player`.
    LiteralPrefix,
    /// The referencing functions share a stem: `Widget_getWidth` → `Widget`.
    FunctionStem,
    /// Neither yielded anything usable, so the name is the cluster's address.
    Address,
}

/// One field of a struct inferred from string literals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredField {
    /// Field name, taken from the literal that named it.
    pub name: String,
    /// The kind the literal's shape suggests.
    pub field_type: FieldType,
    /// Size estimated from the kind. `None` when the kind has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Offset estimated by accumulating the sizes of the fields before it.
    /// `None` when a field's size is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// The literal this field was inferred from.
    pub source_value: String,
    /// Address of that literal.
    pub source_address: u64,
}

/// A struct candidate inferred from clustered string literals.
///
/// Literals the same functions point at are grouped together, and a group
/// large enough to read as a field list becomes a candidate: the literals
/// name the fields, and the confidence score says how far the evidence
/// supports reading them as one struct. Nothing here was declared in the
/// program — a candidate is a hypothesis for the translator to test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredStruct {
    /// Name derived from the cluster; see [`InferredStruct::name_origin`].
    pub name: String,
    /// Where the name came from.
    pub name_origin: NameOrigin,
    /// Fields, in literal-address order.
    pub fields: Vec<InferredField>,
    /// Confidence that the cluster is one struct, 0–100.
    pub confidence: Confidence,
    /// The functions whose cross-references tie the literals together.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_by: Vec<String>,
}

impl InferredStruct {
    /// Whether the name came from the data rather than the cluster's address.
    pub fn is_named(&self) -> bool {
        self.name_origin != NameOrigin::Address
    }

    /// Estimated size: the sum of the field sizes, or `None` when any one of
    /// them is unknown.
    pub fn size(&self) -> Option<u64> {
        self.fields.iter().map(|f| f.size).sum()
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a Type Manager record as prompt data. Structure fields keep
/// their offsets; enum members arrive as fields whose "type" is the
/// member value and whose offset is unknown (`-1`).
impl From<&NamedType> for StructuredData {
    fn from(named: &NamedType) -> Self {
        let fields = named
            .fields
            .iter()
            .map(|f| calxgloss_prompts::StructField {
                name: f.name.clone(),
                type_: f.type_name.clone(),
                offset: f.offset as i64,
            })
            .chain(
                named
                    .members
                    .iter()
                    .map(|m| calxgloss_prompts::StructField {
                        name: m.name.clone(),
                        type_: m.value.to_string(),
                        offset: -1,
                    }),
            )
            .collect();
        Self {
            name: named.name.clone(),
            size: named.size.unwrap_or(0) as usize,
            fields,
        }
    }
}

/// Render an inferred candidate as prompt data. Field types are the C
/// declarations the inference suggested; offsets are estimates and stay
/// unknown (`-1`) when the candidate could not place a field.
impl From<&InferredStruct> for StructuredData {
    fn from(candidate: &InferredStruct) -> Self {
        let fields = candidate
            .fields
            .iter()
            .map(|f| calxgloss_prompts::StructField {
                name: f.name.clone(),
                type_: f.field_type.c_type().to_string(),
                offset: f.offset.map(|o| o as i64).unwrap_or(-1),
            })
            .collect();
        Self {
            name: candidate.name.clone(),
            size: candidate.size().unwrap_or(0) as usize,
            fields,
        }
    }
}

// ============================================================
// Persisted database
// ============================================================

/// The recovered type database for one binary — the document persisted
/// to `re/analysis/typesdb/{dll}.json`.
///
/// The three sections are the outputs of the three recovery engines:
/// [`NamedType`]s from the Type Manager scan, [`Vtable`]s from vtable
/// detection, and [`InferredStruct`]s from string-guided inference. Each
/// section keeps a stable order — path, address, confidence — so two
/// scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDatabase {
    /// Provenance of the scan that produced this database.
    pub metadata: ScanMetadata,
    /// Named types from Ghidra's Type Manager, in Type Manager path
    /// order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_types: Vec<NamedType>,
    /// Detected vtables, in address order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vtables: Vec<Vtable>,
    /// Struct candidates from string-guided inference, highest
    /// confidence first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inferred_structs: Vec<InferredStruct>,
}

impl TypeDatabase {
    /// An empty database for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            named_types: Vec::new(),
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        }
    }

    /// The named type stored at a Type Manager path, e.g.
    /// `/pe/IMAGE_DOS_HEADER`. Paths are unique; type names are not.
    pub fn find_named_type(&self, path: &str) -> Option<&NamedType> {
        self.named_types.iter().find(|t| t.path == path)
    }

    /// The vtable at an address — the stable identity of a table whose
    /// label is usually just `vftable`.
    pub fn find_vtable(&self, address: u64) -> Option<&Vtable> {
        self.vtables.iter().find(|v| v.address == address)
    }

    /// Whether the scan recovered nothing at all.
    pub fn is_empty(&self) -> bool {
        self.named_types.is_empty() && self.vtables.is_empty() && self.inferred_structs.is_empty()
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

    #[test]
    fn vtable_serde_round_trips() {
        let vtable = Vtable {
            address: 0x1801306f0,
            label: "vftable".into(),
            size: 40,
            meta_ptr_address: Some(0x1801306e8),
            methods: vec![
                VtableMethod {
                    slot: 0,
                    address: 0x18003ab00,
                    name: Some("FUN_18003ab00".into()),
                },
                VtableMethod {
                    slot: 1,
                    address: 0x18003e750,
                    name: None,
                },
            ],
            class_name: Some("UdpLibrary::UdpRefCount".into()),
            base_classes: vec!["Base".into()],
            is_com_interface: false,
        };
        let json = serde_json::to_string(&vtable).unwrap();
        let back: Vtable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vtable);
        assert!(vtable.is_confirmed());
    }

    #[test]
    fn empty_vtable_sections_are_not_serialized() {
        let vtable = Vtable {
            address: 0x1801306f0,
            label: "vftable".into(),
            size: 40,
            meta_ptr_address: None,
            methods: Vec::new(),
            class_name: None,
            base_classes: Vec::new(),
            is_com_interface: false,
        };
        let json = serde_json::to_string(&vtable).unwrap();
        assert!(!json.contains("\"methods\""));
        assert!(!json.contains("\"class_name\""));
        assert!(!json.contains("\"base_classes\""));
        assert!(!json.contains("\"meta_ptr_address\""));
        assert!(!vtable.is_confirmed());
    }

    #[test]
    fn inferred_struct_serde_round_trips() {
        let candidate = InferredStruct {
            name: "Player".into(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x".into(),
                    source_address: 0x1801_29350,
                },
                InferredField {
                    name: "name".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(4),
                    source_value: "player.name".into(),
                    source_address: 0x1801_29360,
                },
            ],
            confidence: Confidence::new(79),
            referenced_by: vec!["FUN_18000b620".into()],
        };
        let json = serde_json::to_string(&candidate).unwrap();
        // Kinds and origins serialize snake_case, matching the workspace's
        // serde convention.
        assert!(json.contains("\"field_type\":\"integer\""));
        assert!(json.contains("\"name_origin\":\"literal_prefix\""));
        let back: InferredStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(back, candidate);
        assert!(candidate.is_named());
        assert_eq!(candidate.size(), Some(12));
    }

    #[test]
    fn an_unclassifiable_field_carries_no_layout_and_an_empty_section_is_omitted() {
        let candidate = InferredStruct {
            name: "strings_at_180129350".into(),
            name_origin: NameOrigin::Address,
            fields: vec![InferredField {
                name: "mystery".into(),
                field_type: FieldType::Unknown,
                size: None,
                offset: None,
                source_value: "mystery".into(),
                source_address: 0x1801_29350,
            }],
            confidence: Confidence::new(28),
            referenced_by: Vec::new(),
        };
        let json = serde_json::to_string(&candidate).unwrap();
        assert!(!json.contains("\"size\""));
        assert!(!json.contains("\"offset\""));
        assert!(!json.contains("\"referenced_by\""));
        assert!(!candidate.is_named());
        assert_eq!(candidate.size(), None);
    }

    #[test]
    fn field_type_suggests_a_declaration_and_a_size() {
        assert_eq!(FieldType::String.to_string(), "char *");
        assert_eq!(FieldType::Integer.c_type(), "int");
        assert_eq!(FieldType::Boolean.suggested_size(8), Some(1));
        assert_eq!(FieldType::String.suggested_size(4), Some(4));
        assert_eq!(FieldType::Unknown.suggested_size(8), None);
    }

    #[test]
    fn a_named_struct_converts_with_field_offsets_and_size() {
        let recovered = NamedType {
            fields: vec![
                StructField {
                    name: "e_magic".into(),
                    offset: 0,
                    size: 2,
                    type_name: "char[2]".into(),
                },
                StructField {
                    name: "e_lfanew".into(),
                    offset: 60,
                    size: 4,
                    type_name: "dword".into(),
                },
            ],
            ..NamedType::from_listing(
                &entry("IMAGE_DOS_HEADER", "pe", Some(128)),
                TypeKind::Struct,
            )
        };
        let rendered = StructuredData::from(&recovered);
        assert_eq!(rendered.name, "IMAGE_DOS_HEADER");
        assert_eq!(rendered.size, 128);
        assert_eq!(rendered.fields.len(), 2);
        assert_eq!(rendered.fields[1].name, "e_lfanew");
        assert_eq!(rendered.fields[1].type_, "dword");
        assert_eq!(rendered.fields[1].offset, 60);
    }

    #[test]
    fn enum_members_convert_after_the_fields_holding_their_value() {
        let recovered = NamedType {
            fields: vec![StructField {
                name: "header".into(),
                offset: 0,
                size: 4,
                type_name: "dword".into(),
            }],
            members: vec![
                EnumMember {
                    name: "Idle".into(),
                    value: 0,
                },
                EnumMember {
                    name: "Running".into(),
                    value: 1,
                },
            ],
            ..NamedType::from_listing(&entry("Mode", "excpt.h", None), TypeKind::Enum)
        };
        let rendered = StructuredData::from(&recovered);
        assert_eq!(rendered.size, 0, "a type with no known size reports zero");
        // Structure fields come first, then the enum members.
        assert_eq!(rendered.fields[0].name, "header");
        assert_eq!(rendered.fields[1].name, "Idle");
        assert_eq!(rendered.fields[2].name, "Running");
        assert_eq!(
            rendered.fields[2].type_, "1",
            "the member value is its type"
        );
        assert_eq!(rendered.fields[2].offset, -1);
    }

    #[test]
    fn an_inferred_candidate_converts_with_suggested_c_types() {
        let candidate = InferredStruct {
            name: "Player".into(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x".into(),
                    source_address: 0x1801_29350,
                },
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: None,
                    source_value: "player.label".into(),
                    source_address: 0x1801_29360,
                },
            ],
            confidence: Confidence::new(79),
            referenced_by: Vec::new(),
        };
        let rendered = StructuredData::from(&candidate);
        assert_eq!(rendered.name, "Player");
        assert_eq!(rendered.size, 12, "both fields carry a size");
        assert_eq!(rendered.fields[0].type_, "int");
        assert_eq!(rendered.fields[0].offset, 0);
        assert_eq!(rendered.fields[1].type_, "char *");
        assert_eq!(
            rendered.fields[1].offset, -1,
            "an unplaced field stays unknown"
        );
    }

    #[test]
    fn an_inferred_candidate_without_a_size_estimate_reports_zero() {
        let candidate = InferredStruct {
            name: "strings_at_180129350".into(),
            name_origin: NameOrigin::Address,
            fields: vec![InferredField {
                name: "mystery".into(),
                field_type: FieldType::Unknown,
                size: None,
                offset: None,
                source_value: "mystery".into(),
                source_address: 0x1801_29350,
            }],
            confidence: Confidence::new(28),
            referenced_by: Vec::new(),
        };
        let rendered = StructuredData::from(&candidate);
        assert_eq!(rendered.size, 0);
        assert_eq!(rendered.fields[0].type_, "undefined");
        assert_eq!(rendered.fields[0].offset, -1);
    }

    fn metadata() -> ScanMetadata {
        ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
        }
    }

    fn vtable_at(address: u64) -> Vtable {
        Vtable {
            address,
            label: "vftable".into(),
            size: 40,
            meta_ptr_address: None,
            methods: Vec::new(),
            class_name: None,
            base_classes: Vec::new(),
            is_com_interface: false,
        }
    }

    #[test]
    fn type_database_serde_round_trips_all_three_sections() {
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![NamedType::from_listing(
                &entry("IMAGE_DOS_HEADER", "pe", Some(128)),
                TypeKind::Struct,
            )],
            vtables: vec![vtable_at(0x1801306f0)],
            inferred_structs: vec![InferredStruct {
                name: "Player".into(),
                name_origin: NameOrigin::LiteralPrefix,
                fields: Vec::new(),
                confidence: Confidence::new(79),
                referenced_by: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&db).unwrap();
        let back: TypeDatabase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, db);
        assert!(!back.is_empty());
    }

    #[test]
    fn a_metadata_only_database_omits_empty_sections_and_reads_back() {
        let db = TypeDatabase::new(metadata());
        let json = serde_json::to_string(&db).unwrap();
        assert!(!json.contains("\"named_types\""));
        assert!(!json.contains("\"vtables\""));
        assert!(!json.contains("\"inferred_structs\""));
        let back: TypeDatabase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, db);
        assert!(back.is_empty());
    }

    #[test]
    fn lookups_key_on_type_path_and_vtable_address() {
        // Type names repeat across categories; paths and addresses do not.
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![
                NamedType::from_listing(&entry("FOO", "pe", Some(4)), TypeKind::Struct),
                NamedType::from_listing(&entry("FOO", "excpt.h", Some(8)), TypeKind::Union),
            ],
            vtables: vec![vtable_at(0x1801306f0)],
            inferred_structs: Vec::new(),
        };
        assert_eq!(db.find_named_type("/pe/FOO").unwrap().category, "pe");
        assert_eq!(
            db.find_named_type("/excpt.h/FOO").unwrap().kind,
            TypeKind::Union
        );
        assert!(db.find_named_type("/nope/FOO").is_none());
        assert!(db.find_vtable(0x1801306f0).is_some());
        assert!(db.find_vtable(0x180000000).is_none());
    }

    #[test]
    fn scan_metadata_new_stamps_the_current_time() {
        let meta = ScanMetadata::new("eqmain.dll");
        assert_eq!(meta.binary, "eqmain.dll");
        assert!(meta.scanned_at > 0);
        assert_eq!(meta.duration_secs, 0);
    }
}
