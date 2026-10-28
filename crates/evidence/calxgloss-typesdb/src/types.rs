//! Core data types for the recovered type database.
//!
//! This module holds the serialized shape of everything the recovery scans
//! produce:
//!
//! - [`NamedType`], [`TypeKind`], [`StructField`]: named types read from
//!   the analysis engine's type listing (struct, class, union, enum), with
//!   field layouts.
//! - `Vtable`, `VtableMethod`: detected vtables with resolved method pointers
//!   and base-class inheritance.
//! - `InferredStruct`, `InferredField`, `FieldType`: struct layouts inferred
//!   from string-literal clustering, with evidence confidence scores.
//! - `TypeDatabase`, `ScanMetadata`: the persisted per-binary document and
//!   its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`. The seam's wire records
//! convert into recovered records via `From<&StructFieldLayout>` and
//! `From<&calxgloss_decomp::EnumMember>`. The seam's shapes and the
//! persisted shapes stay deliberately split, and these impls are the only
//! mapping between them. Recovered records also convert into prompt data:
//! `From<&NamedType>` and `From<&InferredStruct>` build a
//! [`calxgloss_prompts::StructuredData`] for the translation prompts.

use crate::stl::StlKind;
use calxgloss_decomp::{DataTypeEntry, EnumDefinition, StructFieldLayout, StructLayout};
use calxgloss_prompts::StructuredData;
use serde::{Deserialize, Serialize};
use std::fmt;

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence confidence score. Both live in
// `calxgloss-types` so every evidence engine crate keys its artifacts and
// scores the same way. They are re-exported here so
// `calxgloss_typesdb::types::*` keeps resolving for existing callers.
pub use calxgloss_types::{Confidence, ScanMetadata};

// ============================================================
// Type kind
// ============================================================

/// The kind of a named type in the analysis engine's type listing.
///
/// The bridge classifies every Type Manager entry as struct, union, enum,
/// typedef, pointer, array, function, or primitive. The analysis engine
/// stores C++ classes as structures, so a recovered class arrives as
/// [`TypeKind::Struct`]. [`TypeKind::Class`] is reserved for kinds
/// confirmed by other signals (RTTI, vtable linkage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    /// A structure (or a C++ class, which the analysis engine stores as a structure).
    Struct,
    /// A class confirmed by a signal beyond its structure layout.
    Class,
    /// A union. The bridge classifies unions but exposes no layout endpoint,
    /// so a recovered union records its size but no fields.
    Union,
    /// An enumeration with named members.
    Enum,
    /// A typedef alias. The endpoints the scan reads do not report the
    /// alias target, so a typedef records its size only.
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
/// The persisted counterpart of the wire shape `calxgloss_decomp::StructFieldLayout`.
/// The two stay deliberately split. `calxgloss_decomp::StructFieldLayout` is
/// the parsed `struct_layout()` answer owned by the seam; this is the
/// serde'd recovered record. [`From<&StructFieldLayout>`] is the only
/// mapping between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name as the analysis engine labels it. `(unnamed)` for anonymous fields.
    pub name: String,
    /// Byte offset of the field from the start of the structure.
    pub offset: u64,
    /// Size of the field in bytes.
    pub size: u64,
    /// The field's data type name, e.g. `dword` or `char[2]`.
    pub type_name: String,
    /// The Type Manager path of the recovered named type that this field's
    /// `type_name` refers to. The scan's nesting pass sets it when exactly
    /// one recovered type has that name; paths, not names, are the unique
    /// keys. `None` for a field typed as a primitive or an unrecovered
    /// type, for a name several recovered types share, and for databases
    /// written before the nesting pass existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_type: Option<String>,
    /// The kind of the linked type, stored with the link. It keeps a field
    /// typed as a recovered union from being misread as a struct. `None`
    /// exactly when `linked_type` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_kind: Option<TypeKind>,
}

impl StructField {
    /// Whether the nesting pass linked this field to a recovered named
    /// type, making its layout part of a tree rather than a flat list.
    pub fn is_nested(&self) -> bool {
        self.linked_type.is_some()
    }
}

/// One member of a recovered enumeration.
///
/// The persisted counterpart of the wire shape `calxgloss_decomp::EnumMember`.
/// The two records are identical today but stay split on purpose, for the
/// same reason as [`StructField`].
/// [`From<&calxgloss_decomp::EnumMember>`] is the only mapping between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumMember {
    /// Member name, e.g. `ExceptionContinueExecution`.
    pub name: String,
    /// Member value. Signed because the analysis engine's enums may hold
    /// negative values.
    pub value: i64,
}

/// Wire → recovered conversions for the layout leaves.
///
/// These impls are the only place where the seam's record shapes and the
/// persisted recovered shapes meet. The field copies live here rather than
/// inline in [`NamedType::from_struct`] / [`NamedType::from_enum`], so a
/// change to the wire shapes breaks exactly one compile.
impl From<&StructFieldLayout> for StructField {
    fn from(field: &StructFieldLayout) -> Self {
        Self {
            name: field.field_name.clone(),
            offset: field.offset,
            size: field.size,
            type_name: field.type_name.clone(),
            // The nesting pass fills the links in after the scans assemble.
            linked_type: None,
            linked_kind: None,
        }
    }
}

impl From<&calxgloss_decomp::EnumMember> for EnumMember {
    fn from(member: &calxgloss_decomp::EnumMember) -> Self {
        Self {
            name: member.name.clone(),
            value: member.value,
        }
    }
}

// ============================================================
// Named types
// ============================================================

/// A named type recovered from the analysis engine's type listing.
///
/// The Type Manager holds every type the program knows about, including
/// types never applied to a symbol. So a `NamedType` can describe a type
/// that appears nowhere in the listing. `path` is the Type Manager path
/// and is unique. Type *names* are not unique, so the database keys by
/// path.
///
/// A type whose layout probe found nothing or failed is still recorded.
/// Its `size` comes from the listing and its `fields`/`members` stay
/// empty. A type known to exist is worth keeping even without its
/// layout, and `kind` records what the scan could establish about it.
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
    /// Size in bytes. `None` when the analysis engine reports the size as `variable`.
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
    /// The STL/MFC family this type's name matches. The scan's STL
    /// flagging pass sets it when the recovered name spells a known
    /// standard-library shape (`basic_string`/`CString`, `vector`, `list`,
    /// the `map`/`set` family, a smart pointer). Flag-only: the record
    /// stays in every section and answers every lookup. `None` for the
    /// program's own types and for databases written before the flagging
    /// pass existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stl_kind: Option<StlKind>,
}

impl NamedType {
    /// A type recorded from the listing alone, without a layout.
    ///
    /// This is the degraded shape: the scan knows the type exists, which
    /// category it sits in, and how large it is, but nothing about its
    /// internals.
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
            // The STL flagging pass fills the flag in after the scans assemble.
            stl_kind: None,
        }
    }

    /// A structure confirmed by a `struct_layout()` answer.
    ///
    /// When the layout and the listing disagree, the layout's size and
    /// alignment are used. The layout is the authoritative read of the
    /// same type, and the listing may report the size as `variable`.
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
            stl_kind: None,
        }
    }

    /// An enumeration confirmed by an `enum_values()` answer.
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
            stl_kind: None,
        }
    }

    /// Whether a layout or member list was recovered for this type.
    pub fn has_layout(&self) -> bool {
        !self.fields.is_empty() || !self.members.is_empty()
    }

    /// Whether the STL flagging pass recognized this type's name as a
    /// standard-library shape. The flag never removes the record from a
    /// section or a lookup.
    pub fn is_stl(&self) -> bool {
        self.stl_kind.is_some()
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
    /// The function the analysis engine has at that address. `None` when the pointer lands
    /// outside any known function body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A vtable recovered from the program's defined data.
///
/// Ghidra names every MSVC vtable `vftable`, so the label identifies
/// nothing on its own; the database keys by address. When a
/// `vftable_meta_ptr` entry precedes a table, the pair confirms the RTTI
/// pattern, and the scan follows the RTTI chain to recover the class name
/// and base classes. A table without that pair is still a vtable; it just
/// has no RTTI record to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtable {
    /// Address of the table itself.
    pub address: u64,
    /// The label the analysis engine shows, e.g. `vftable`.
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
    /// The STL/MFC family the RTTI-demangled `class_name` matches — set by
    /// the scan's STL flagging pass. Flag-only: a flagged table stays in
    /// the section and answers address lookups. `None` for the program's
    /// own classes, for an unresolved class name, and for databases
    /// written before the flagging pass existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stl_kind: Option<StlKind>,
}

impl Vtable {
    /// Whether the table had the `vftable_meta_ptr` RTTI confirmation.
    pub fn is_confirmed(&self) -> bool {
        self.meta_ptr_address.is_some()
    }

    /// Whether the STL flagging pass recognized the class name as a
    /// standard-library shape.
    pub fn is_stl(&self) -> bool {
        self.stl_kind.is_some()
    }
}

// ============================================================
// Inferred structs
// ============================================================

/// The kind inferred for one string-inferred field.
///
/// The kind comes from the *shape* of the literal that named the field:
/// `width=100` suggests an integer, `ratio=0.5` suggests a float,
/// `enabled=true` suggests a flag, and a bare identifier suggests text.
/// It is a suggestion for the translator, not a fact read out of the
/// program.
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
/// The name is part of the evidence report: a candidate named from the
/// data it came from is a better hypothesis than one named after its own
/// address. The variants are ordered from strongest evidence to weakest;
/// this order is the confidence ladder of string-guided inference.
/// [`NameOrigin::confidence_bonus`] converts the ladder into evidence
/// confidence points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOrigin {
    /// The candidate links to an RTTI-confirmed vtable and the name is that
    /// table's demangled class name — the program's own name for the type.
    VtableClass,
    /// The literals share a qualifier: `player.x`, `player.y` → `Player`.
    LiteralPrefix,
    /// The referencing functions share a stem: `Widget_getWidth` → `Widget`.
    FunctionStem,
    /// Neither yielded anything usable, so the name is the cluster's address.
    Address,
}

impl NameOrigin {
    /// The evidence confidence points this origin adds to a candidate's score.
    ///
    /// The points follow the order the variants are declared in: a name
    /// the program itself stores (an RTTI class name) scores higher than
    /// one guessed from the literals, which scores higher than one guessed
    /// from function stems, which scores higher than the address fallback.
    /// These points are the single source of the ladder, so a candidate
    /// re-named after linking is re-scored by using the new origin's points
    /// instead of the old origin's.
    pub fn confidence_bonus(&self) -> u8 {
        match self {
            NameOrigin::VtableClass => 35,
            NameOrigin::LiteralPrefix => 25,
            NameOrigin::FunctionStem => 15,
            NameOrigin::Address => 0,
        }
    }
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
    /// The STL/MFC family the field's suggested type matches. The scan's
    /// STL flagging pass sets it, so a text-typed field reads as the
    /// string family rather than as an untyped pointer. Flag-only. `None`
    /// for a suggested type with no shape and for databases written before
    /// the flagging pass existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stl_kind: Option<StlKind>,
}

impl InferredField {
    /// Whether the STL flagging pass recognized this field's suggested
    /// type as a standard-library shape.
    pub fn is_stl(&self) -> bool {
        self.stl_kind.is_some()
    }
}

/// A struct candidate inferred from clustered string literals.
///
/// The scan groups the literals that the same functions point at. A
/// group large enough to look like a field list becomes a candidate:
/// the literals give the field names, and the evidence confidence score
/// says how far the evidence supports reading them as one struct. The
/// program declares none of this — a candidate is a hypothesis for the
/// translator to test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredStruct {
    /// Name derived from the cluster; see [`InferredStruct::name_origin`].
    pub name: String,
    /// Where the name came from.
    pub name_origin: NameOrigin,
    /// Fields, in literal-address order.
    pub fields: Vec<InferredField>,
    /// Evidence confidence that the cluster is one struct, 0–100.
    pub confidence: Confidence,
    /// Every function that references the candidate's literals. This
    /// includes hub functions: they point at so many literals that no one
    /// struct can be clustered from them, but they still support the
    /// candidates whose literals they read. The cross-reference merge pass
    /// compares these function sets across candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_by: Vec<String>,
    /// The address of the RTTI-confirmed vtable this candidate was linked
    /// to. The linking pass sets it when the candidate's referencing
    /// functions include that table's methods; that is why the name then
    /// becomes the table's class name ([`NameOrigin::VtableClass`]).
    /// `None` for an unlinked candidate, and for databases written before
    /// the linking pass existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_vtable: Option<u64>,
    /// How many half-candidates the cross-reference merge pass combined into
    /// this one — `Some(n)` with `n ≥ 2` when the candidate is the union of
    /// `n` candidates whose referencing functions overlapped, `None` when
    /// the pass left it alone. Candidates written before the merge pass
    /// existed load as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_from: Option<usize>,
}

impl InferredStruct {
    /// Whether the name came from the data rather than the cluster's address.
    pub fn is_named(&self) -> bool {
        self.name_origin != NameOrigin::Address
    }

    /// Whether the candidate was linked to an RTTI-confirmed vtable, and so
    /// has that table's class name.
    pub fn is_linked(&self) -> bool {
        self.linked_vtable.is_some()
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
/// their offsets. Enum members arrive as fields whose "type" is the
/// member value and whose offset is unknown (`-1`). A field the nesting
/// pass linked to a recovered named type shows its kind in front of the
/// type name — `union VALUE`, not just `VALUE` — so the layout reads as
/// a tree inside the existing field list, with no new prompt section. A
/// type the STL flagging pass recognized shows its family in the type
/// description — `basic_string<…> (STL string)` — so the translator maps
/// it to a Rust equivalent instead of inventing a raw layout.
impl From<&NamedType> for StructuredData {
    fn from(named: &NamedType) -> Self {
        let fields = named
            .fields
            .iter()
            .map(|f| calxgloss_prompts::StructField {
                name: f.name.clone(),
                type_: match f.linked_kind {
                    Some(kind) => format!("{kind} {}", f.type_name),
                    None => f.type_name.clone(),
                },
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
            name: match named.stl_kind {
                Some(kind) => format!("{} (STL {kind})", named.name),
                None => named.name.clone(),
            },
            size: named.size.unwrap_or(0) as usize,
            fields,
        }
    }
}

/// Render an inferred candidate as prompt data. Field types are the C
/// declarations the inference suggested. Offsets are estimates, and stay
/// unknown (`-1`) when the candidate could not place a field. A field
/// the STL flagging pass recognized shows its family in the type —
/// `char * (STL string)` — so the translator maps it to a Rust string
/// type instead of hand-rolling a buffer.
impl From<&InferredStruct> for StructuredData {
    fn from(candidate: &InferredStruct) -> Self {
        let fields = candidate
            .fields
            .iter()
            .map(|f| calxgloss_prompts::StructField {
                name: f.name.clone(),
                type_: match f.stl_kind {
                    Some(kind) => format!("{} (STL {kind})", f.field_type.c_type()),
                    None => f.field_type.c_type().to_string(),
                },
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
/// The three sections are the products of the crate's three recovery
/// scans: [`NamedType`]s from the Type Manager scan, [`Vtable`]s from
/// vtable detection, and [`InferredStruct`]s from string-guided
/// inference. Each section keeps a stable order: named types by path,
/// vtables by address, candidates by evidence confidence. Two scans of
/// the same program therefore diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDatabase {
    /// Provenance of the scan that produced this database.
    pub metadata: ScanMetadata,
    /// Named types from the analysis engine's type listing, in Type Manager path
    /// order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_types: Vec<NamedType>,
    /// Detected vtables, in address order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vtables: Vec<Vtable>,
    /// Struct candidates from string-guided inference, highest
    /// evidence confidence first.
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
            linked_type: None,
            linked_kind: None,
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
    fn a_nested_field_round_trips_with_its_links() {
        let mut struct_type =
            NamedType::from_listing(&entry("WIDGET", "pe", Some(24)), TypeKind::Struct);
        struct_type.fields.push(StructField {
            name: "payload".into(),
            offset: 4,
            size: 8,
            type_name: "MY_UNION".into(),
            linked_type: Some("/sys/MY_UNION".into()),
            linked_kind: Some(TypeKind::Union),
        });

        let json = serde_json::to_string(&struct_type).unwrap();
        assert!(json.contains("\"linked_type\":\"/sys/MY_UNION\""));
        assert!(json.contains("\"linked_kind\":\"union\""));
        let back: NamedType =
            serde_json::from_str(&json).expect("a nested field should round-trip");
        assert_eq!(back, struct_type);
        assert!(back.fields[0].is_nested());
    }

    #[test]
    fn a_field_written_before_the_nesting_pass_still_loads() {
        // The shipped MVP shape: fields have no `linked_type` or
        // `linked_kind` key. The new fields default, so old cached
        // documents keep loading.
        let json = r#"{
            "name": "IMAGE_DOS_HEADER",
            "kind": "struct",
            "category": "pe",
            "path": "/pe/IMAGE_DOS_HEADER",
            "size": 128,
            "fields": [{
                "name": "e_magic",
                "offset": 0,
                "size": 2,
                "type_name": "char[2]"
            }]
        }"#;
        let back: NamedType = serde_json::from_str(json).expect("the mvp-shape field should load");
        assert_eq!(back.fields[0].type_name, "char[2]");
        assert_eq!(back.fields[0].linked_type, None);
        assert_eq!(back.fields[0].linked_kind, None);
        assert!(!back.fields[0].is_nested());
    }

    #[test]
    fn a_flagged_named_type_round_trips_with_its_stl_kind() {
        let mut recovered =
            NamedType::from_listing(&entry("basic_string", "pe", Some(24)), TypeKind::Class);
        recovered.stl_kind = Some(StlKind::String);

        let json = serde_json::to_string(&recovered).expect("a flagged type should serialize");
        assert!(json.contains("\"stl_kind\":\"string\""));
        let back: NamedType =
            serde_json::from_str(&json).expect("a flagged type should round-trip");
        assert_eq!(back, recovered);
        assert!(back.is_stl());
    }

    #[test]
    fn a_flagged_vtable_and_inferred_field_round_trip_with_their_kinds() {
        let vtable = Vtable {
            stl_kind: Some(StlKind::Vector),
            ..vtable_at(0x1801_306f0)
        };
        let json = serde_json::to_string(&vtable).expect("a flagged vtable should serialize");
        assert!(json.contains("\"stl_kind\":\"vector\""));
        let back: Vtable = serde_json::from_str(&json).expect("a flagged vtable should round-trip");
        assert_eq!(back, vtable);
        assert!(back.is_stl());

        let candidate = InferredStruct {
            name: "strings_at_180129350".into(),
            name_origin: NameOrigin::Address,
            fields: vec![InferredField {
                name: "payload".into(),
                field_type: FieldType::Unknown,
                size: None,
                offset: None,
                source_value: "payload".into(),
                source_address: 0x1801_29350,
                stl_kind: Some(StlKind::Map),
            }],
            confidence: Confidence::new(30),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
        };
        let json = serde_json::to_string(&candidate).expect("a flagged field should serialize");
        assert!(json.contains("\"stl_kind\":\"map\""));
        let back: InferredStruct =
            serde_json::from_str(&json).expect("a flagged field should round-trip");
        assert_eq!(back, candidate);
        assert!(back.fields[0].is_stl());
    }

    #[test]
    fn records_written_before_the_stl_flag_still_load() {
        // The shipped MVP shape: no record has an `stl_kind` key.
        // The field defaults, so old cached documents keep loading.
        let named: NamedType = serde_json::from_str(
            r#"{
                "name": "IMAGE_DOS_HEADER",
                "kind": "struct",
                "category": "pe",
                "path": "/pe/IMAGE_DOS_HEADER",
                "size": 128
            }"#,
        )
        .expect("a pre-STL named type should load");
        assert_eq!(named.stl_kind, None);
        assert!(!named.is_stl());

        let vtable: Vtable = serde_json::from_str(
            r#"{
                "address": 98823820528,
                "label": "vftable",
                "size": 40,
                "methods": [],
                "is_com_interface": false
            }"#,
        )
        .expect("a pre-STL vtable should load");
        assert_eq!(vtable.stl_kind, None);

        let field: InferredField = serde_json::from_str(
            r#"{
                "name": "x",
                "field_type": "integer",
                "size": 4,
                "offset": 0,
                "source_value": "player.x",
                "source_address": 103079856976
            }"#,
        )
        .expect("a pre-STL inferred field should load");
        assert_eq!(field.stl_kind, None);
        assert!(!field.is_stl());
    }

    #[test]
    fn from_struct_maps_the_layout_fields() {
        // The IMAGE_DOS_HEADER layout as the `struct_layout()` answer renders it.
        let layout = StructLayout {
            name: "IMAGE_DOS_HEADER".into(),
            size: 128,
            alignment: 1,
            fields: vec![
                calxgloss_decomp::StructFieldLayout {
                    offset: 0,
                    size: 2,
                    type_name: "char[2]".into(),
                    field_name: "e_magic".into(),
                },
                calxgloss_decomp::StructFieldLayout {
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
                calxgloss_decomp::EnumMember {
                    name: "ExceptionContinueExecution".into(),
                    value: 0,
                },
                calxgloss_decomp::EnumMember {
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
            stl_kind: None,
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
            stl_kind: None,
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
                    stl_kind: None,
                },
                InferredField {
                    name: "name".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(4),
                    source_value: "player.name".into(),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(79),
            referenced_by: vec!["FUN_18000b620".into()],
            linked_vtable: None,
            merged_from: None,
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
    fn a_linked_candidate_round_trips_with_its_vtable_link() {
        let candidate = InferredStruct {
            name: "Widget".into(),
            name_origin: NameOrigin::VtableClass,
            fields: vec![InferredField {
                name: "x".into(),
                field_type: FieldType::Integer,
                size: Some(4),
                offset: Some(0),
                source_value: "widget.x".into(),
                source_address: 0x1801_29350,
                stl_kind: None,
            }],
            confidence: Confidence::new(81),
            referenced_by: vec!["FUN_18003ab00".into()],
            linked_vtable: Some(0x1801_306f0),
            merged_from: None,
        };
        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("\"name_origin\":\"vtable_class\""));
        assert!(json.contains(&format!("\"linked_vtable\":{}", 0x1801_306f0u64)));
        let back: InferredStruct =
            serde_json::from_str(&json).expect("a linked candidate should round-trip");
        assert_eq!(back, candidate);
        assert!(back.is_linked());
    }

    #[test]
    fn a_candidate_written_before_the_linking_pass_still_loads() {
        // The shipped MVP shape: no `linked_vtable` key, no `merged_from`
        // key, and no `vtable_class` origin anywhere. The new fields
        // default, so old cached documents keep loading.
        let json = r#"{
            "name": "Player",
            "name_origin": "literal_prefix",
            "fields": [],
            "confidence": 79,
            "referenced_by": ["FUN_18000b620"]
        }"#;
        let back: InferredStruct =
            serde_json::from_str(json).expect("the mvp-shape candidate should load");
        assert_eq!(back.name_origin, NameOrigin::LiteralPrefix);
        assert_eq!(back.linked_vtable, None);
        assert!(!back.is_linked());
        assert_eq!(back.merged_from, None);
    }

    #[test]
    fn a_merged_candidate_round_trips_with_its_merge_marker() {
        let candidate = InferredStruct {
            name: "Widget".into(),
            name_origin: NameOrigin::VtableClass,
            fields: vec![
                InferredField {
                    name: "width".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "widget.width=1".into(),
                    source_address: 0x1801_29400,
                    stl_kind: None,
                },
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(4),
                    source_value: "widget.label".into(),
                    source_address: 0x1801_29420,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(97),
            referenced_by: vec!["FUN_18003ab00".into(), "FUN_widget_access".into()],
            linked_vtable: Some(0x1801_306f0),
            merged_from: Some(2),
        };
        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("\"merged_from\":2"));
        let back: InferredStruct =
            serde_json::from_str(&json).expect("a merged candidate should round-trip");
        assert_eq!(back, candidate);
        assert_eq!(back.merged_from, Some(2));
    }

    #[test]
    fn name_origins_pay_out_the_evidence_ladder() {
        // The vtable class name outranks the guessed names, which outrank
        // the address fallback — the order the variants are declared in.
        assert!(
            NameOrigin::VtableClass.confidence_bonus()
                > NameOrigin::LiteralPrefix.confidence_bonus()
        );
        assert!(
            NameOrigin::LiteralPrefix.confidence_bonus()
                > NameOrigin::FunctionStem.confidence_bonus()
        );
        assert!(
            NameOrigin::FunctionStem.confidence_bonus() > NameOrigin::Address.confidence_bonus()
        );
        assert_eq!(NameOrigin::Address.confidence_bonus(), 0);
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
                stl_kind: None,
            }],
            confidence: Confidence::new(28),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
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
                    linked_type: None,
                    linked_kind: None,
                },
                StructField {
                    name: "e_lfanew".into(),
                    offset: 60,
                    size: 4,
                    type_name: "dword".into(),
                    linked_type: None,
                    linked_kind: None,
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
    fn a_linked_field_renders_its_kind_in_the_prompt_field_list() {
        // Nesting shows up inside the existing field list: a linked
        // field's type includes the linked kind, so a union field cannot
        // be misread as a struct. Unlinked fields stay verbatim.
        let recovered = NamedType {
            fields: vec![
                StructField {
                    name: "mode".into(),
                    offset: 0,
                    size: 4,
                    type_name: "MODES".into(),
                    linked_type: Some("/excpt.h/MODES".into()),
                    linked_kind: Some(TypeKind::Enum),
                },
                StructField {
                    name: "payload".into(),
                    offset: 4,
                    size: 8,
                    type_name: "MY_UNION".into(),
                    linked_type: Some("/sys/MY_UNION".into()),
                    linked_kind: Some(TypeKind::Union),
                },
                StructField {
                    name: "raw".into(),
                    offset: 12,
                    size: 4,
                    type_name: "dword".into(),
                    linked_type: None,
                    linked_kind: None,
                },
            ],
            ..NamedType::from_listing(&entry("WIDGET", "pe", Some(16)), TypeKind::Struct)
        };
        let rendered = StructuredData::from(&recovered);
        assert_eq!(rendered.fields.len(), 3, "no new fields or sections");
        assert_eq!(rendered.fields[0].type_, "enum MODES");
        assert_eq!(rendered.fields[1].type_, "union MY_UNION");
        assert_eq!(rendered.fields[2].type_, "dword");
    }

    #[test]
    fn a_flagged_named_type_names_its_stl_family_in_the_prompt_name() {
        // The STL family is included in the type description, so the
        // translator maps the type to a Rust equivalent instead of
        // inventing a raw layout (issue #140).
        let recovered = NamedType {
            stl_kind: Some(StlKind::String),
            ..NamedType::from_listing(&entry("basic_string", "pe", Some(24)), TypeKind::Class)
        };
        let rendered = StructuredData::from(&recovered);
        assert_eq!(rendered.name, "basic_string (STL string)");

        let plain = NamedType::from_listing(&entry("WIDGET", "pe", Some(8)), TypeKind::Class);
        assert_eq!(StructuredData::from(&plain).name, "WIDGET");
    }

    #[test]
    fn a_flagged_inferred_field_names_its_stl_family_in_the_prompt_type() {
        let candidate = InferredStruct {
            name: "Player".into(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(0),
                    source_value: "Player".into(),
                    source_address: 0x1801_29350,
                    stl_kind: Some(StlKind::String),
                },
                InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(8),
                    source_value: "42".into(),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(79),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
        };
        let rendered = StructuredData::from(&candidate);
        assert_eq!(rendered.fields[0].type_, "char * (STL string)");
        assert_eq!(
            rendered.fields[1].type_, "int",
            "unflagged fields stay verbatim"
        );
    }

    #[test]
    fn enum_members_convert_after_the_fields_holding_their_value() {
        let recovered = NamedType {
            fields: vec![StructField {
                name: "header".into(),
                offset: 0,
                size: 4,
                type_name: "dword".into(),
                linked_type: None,
                linked_kind: None,
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
                    stl_kind: None,
                },
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: None,
                    source_value: "player.label".into(),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(79),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
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
                stl_kind: None,
            }],
            confidence: Confidence::new(28),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
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
            engine: None,
            coverage: None,
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
            stl_kind: None,
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
                linked_vtable: None,
                merged_from: None,
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
