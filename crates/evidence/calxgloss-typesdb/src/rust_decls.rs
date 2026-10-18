//! Rust declarations rendered from the recovered type database.
//!
//! [`render_rust_decls`] turns a [`TypeDatabase`] into one Rust source
//! string: every recovered type with a layout becomes a `#[repr(C)]`
//! struct (or `#[repr(i64)]` enum) a reviewer can read side by side with
//! the translated code. The renderer is pure — data in, string out — and
//! deterministic: it walks each section in its stored order (named types
//! by Type Manager path, then inferred candidates) and stamps no
//! timestamp, so two renders of the same database are byte-identical and
//! a rescan produces a reviewable diff, not churn.
//!
//! The rendering rules (ADR-0013):
//!
//! - **Structs** carry sanitized snake_case fields and explicit
//!   `_pad_{offset}: [u8; n]` fields wherever offsets leave a gap, so the
//!   declared layout matches the recovered one byte for byte.
//! - **Enums** render `#[repr(i64)]` with each member's recovered value.
//! - **Nested fields** — those the nesting pass linked to a recovered
//!   type — reference the inner type's sanitized name, so the file reads
//!   as a type tree.
//! - **STL-flagged types** render as a comment naming their Rust
//!   equivalent (`String`, `Vec<T>`, …), never a hand-rolled layout.
//! - **Layout-less types are skipped entirely**: a record the scan only
//!   knows exists has nothing to declare.
//!
//! The output is a *derived artifact*: regenerated from the loaded
//! database beside the JSON it came from, and never read back.

use std::collections::{HashMap, HashSet};

use crate::stl::StlKind;
use crate::types::{InferredField, InferredStruct, NamedType, StructField, TypeDatabase, TypeKind};

/// Rust keywords and reserved words a sanitized identifier must not spell
/// verbatim; a field or member named one gets a trailing `_` instead.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "box", "break", "const", "continue", "crate", "do", "dyn", "else",
    "enum", "extern", "false", "final", "fn", "for", "if", "impl", "in", "let", "loop", "macro",
    "match", "mod", "move", "mut", "override", "pub", "ref", "return", "self", "Self", "static",
    "struct", "super", "trait", "true", "try", "type", "typeof", "union", "unsafe", "use",
    "virtual", "where", "while", "yield",
];

/// Decompiler builtin type names mapped to their Rust scalar shapes.
///
/// Sizes follow the 64-bit Windows programs this pipeline targets (Ghidra's
/// `long` is the Windows 4-byte `long`). Widths that have no Rust scalar —
/// `undefined3` and friends — become byte arrays so the declared size stays
/// honest.
const PRIMITIVES: &[(&str, &str)] = &[
    ("bool", "bool"),
    ("boolean", "bool"),
    ("char", "i8"),
    ("schar", "i8"),
    ("uchar", "u8"),
    ("byte", "u8"),
    ("ubyte", "u8"),
    ("wchar_t", "u16"),
    ("short", "i16"),
    ("ushort", "u16"),
    ("word", "u16"),
    ("dword", "u32"),
    ("qword", "u64"),
    ("int", "i32"),
    ("uint", "u32"),
    ("long", "i32"),
    ("ulong", "u32"),
    ("longlong", "i64"),
    ("ulonglong", "u64"),
    ("float", "f32"),
    ("double", "f64"),
    ("longdouble", "f64"),
    ("undefined", "u8"),
    ("undefined1", "u8"),
    ("undefined2", "u16"),
    ("undefined3", "[u8; 3]"),
    ("undefined4", "u32"),
    ("undefined5", "[u8; 5]"),
    ("undefined6", "[u8; 6]"),
    ("undefined7", "[u8; 7]"),
    ("undefined8", "u64"),
    ("pointer", "*mut c_void"),
    ("void", "c_void"),
];

/// The Rust type an STL/MFC family maps onto — the hint the comment
/// carries in place of a hand-rolled layout.
fn rust_equivalent(kind: StlKind) -> &'static str {
    match kind {
        StlKind::String => "String",
        StlKind::Vector => "Vec<T>",
        StlKind::List => "Vec<T>",
        StlKind::Map => "BTreeMap<K, V>",
        StlKind::SmartPointer => "Box<T>",
    }
}

/// Render the whole database as one Rust source string.
///
/// Declarations appear in the database's own stored order — named types
/// in Type Manager path order, then inferred candidates in their stored
/// order — and nothing volatile (timestamps, counts) is written, so the
/// same database always renders to the same bytes.
pub fn render_rust_decls(db: &TypeDatabase) -> String {
    let mut renderer = Renderer::new(db);
    renderer.render()
}

/// One render pass: assigns every declared type a unique sanitized name,
/// then writes the declarations in stored order.
struct Renderer<'a> {
    db: &'a TypeDatabase,
    /// Sanitized declaration names, keyed by Type Manager path for named
    /// types — the key a nested field's link resolves through.
    declared: HashMap<&'a str, String>,
    /// Every sanitized name already handed out, so a second `SHARED` in
    /// another category never collides with the first.
    taken: HashSet<String>,
}

impl<'a> Renderer<'a> {
    fn new(db: &'a TypeDatabase) -> Self {
        Self {
            db,
            declared: HashMap::new(),
            taken: HashSet::new(),
        }
    }

    /// Whether this record gets a declaration at all: an STL-flagged type
    /// renders as a comment instead, and a type the scan never laid out
    /// has nothing to declare.
    fn is_declared(named: &NamedType) -> bool {
        !named.is_stl() && named.has_layout()
    }

    fn render(&mut self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "// Rust declarations recovered from {} by `calxgloss typesdb`.\n\
             // Derived artifact: regenerated from the type database on every\n\
             // scan — edit the database, never this file.\n\n\
             #![allow(dead_code, unused_imports)]\n\n\
             use core::ffi::c_void;\n",
            self.db.metadata.binary
        ));

        // Names are assigned in render order before anything is written,
        // so a nested field always references the exact name its inner
        // type was declared under — collision suffixes included.
        for named in &self.db.named_types {
            if Self::is_declared(named) {
                let name = unique_name(&sanitize_type_name(&named.name), &mut self.taken);
                self.declared.insert(named.path.as_str(), name);
            }
        }
        let candidates: Vec<String> = self
            .db
            .inferred_structs
            .iter()
            .map(|c| unique_name(&sanitize_type_name(&c.name), &mut self.taken))
            .collect();

        for named in &self.db.named_types {
            out.push('\n');
            if let Some(kind) = named.stl_kind {
                out.push_str(&format!(
                    "// {} — STL {}: maps to Rust {}; no layout emitted.\n",
                    named.name,
                    kind,
                    rust_equivalent(kind),
                ));
            } else if let Some(name) = self.declared.get(named.path.as_str()) {
                self.render_named_type(named, name, &mut out);
            }
        }
        for (candidate, name) in self.db.inferred_structs.iter().zip(candidates) {
            out.push('\n');
            self.render_candidate(candidate, &name, &mut out);
        }
        out
    }

    fn render_named_type(&self, named: &NamedType, name: &str, out: &mut String) {
        match named.kind {
            TypeKind::Enum => {
                out.push_str(&format!("#[repr(i64)]\npub enum {name} {{\n"));
                let mut taken = HashSet::new();
                for member in &named.members {
                    let member_name = unique_name(&sanitize_type_name(&member.name), &mut taken);
                    out.push_str(&format!("    {member_name} = {},\n", member.value));
                }
                out.push_str("}\n");
            }
            TypeKind::Union => {
                // Unions carry no layout through today's endpoints, but a
                // recovered one would render here, not as a struct.
                out.push_str(&format!("#[repr(C)]\npub union {name} {{\n"));
                self.render_fields(&named.fields, named.size, out);
                out.push_str("}\n");
            }
            _ => {
                out.push_str(&format!("#[repr(C)]\npub struct {name} {{\n"));
                self.render_fields(&named.fields, named.size, out);
                out.push_str("}\n");
            }
        }
    }

    /// Struct fields in offset order, with an explicit padding field
    /// wherever the next field's offset leaves a gap and, when the type's
    /// size is known, after the last field.
    fn render_fields(&self, fields: &[StructField], size: Option<u64>, out: &mut String) {
        let mut taken = HashSet::new();
        let mut cursor = 0u64;
        for field in fields {
            if field.offset > cursor {
                push_padding(out, cursor, field.offset - cursor);
            }
            cursor = cursor.max(field.offset.saturating_add(field.size));
            let field_name = unique_name(&sanitize_field_name(&field.name), &mut taken);
            let (ty, comment) = self.field_type(field);
            push_field(out, &field_name, &ty, comment.as_deref());
        }
        if let Some(total) = size.filter(|total| *total > cursor) {
            push_padding(out, cursor, total - cursor);
        }
    }

    /// The Rust type for one struct field, plus an optional trailing
    /// comment. A linked field references the inner type's declared name;
    /// a link to an STL-flagged type names its Rust equivalent instead.
    fn field_type(&self, field: &StructField) -> (String, Option<String>) {
        if let Some(path) = field.linked_type.as_deref() {
            if let Some(name) = self.declared.get(path) {
                return (name.clone(), None);
            }
            if let Some(kind) = self.db.find_named_type(path).and_then(|t| t.stl_kind) {
                return (
                    rust_equivalent(kind).to_string(),
                    Some(format!("STL {kind} {path}")),
                );
            }
        }
        (map_c_type(&field.type_name), None)
    }

    fn render_candidate(&self, candidate: &InferredStruct, name: &str, out: &mut String) {
        out.push_str(&format!(
            "// Inferred candidate — confidence {}; a hypothesis from\n\
             // string literals, not a layout read from the program.\n\
             #[repr(C)]\npub struct {name} {{\n",
            candidate.confidence.value(),
        ));
        let mut taken = HashSet::new();
        // Offsets are estimates: padding is only honest when every field
        // was placed, so a candidate with any unknown offset lays its
        // fields out bare.
        let placed = candidate.fields.iter().all(|f| f.offset.is_some());
        let mut cursor = 0u64;
        for field in &candidate.fields {
            if let Some(offset) = field.offset {
                if placed && offset > cursor {
                    push_padding(out, cursor, offset - cursor);
                }
                cursor = cursor.max(offset.saturating_add(field.size.unwrap_or(0)));
            }
            let field_name = unique_name(&sanitize_field_name(&field.name), &mut taken);
            let (ty, comment) = candidate_field_type(field);
            push_field(out, &field_name, &ty, comment.as_deref());
        }
        out.push_str("}\n");
    }
}

/// The Rust type for one inferred field, plus an optional trailing
/// comment naming the STL family a flagged field maps onto.
fn candidate_field_type(field: &InferredField) -> (String, Option<String>) {
    match field.stl_kind {
        Some(kind) => (
            rust_equivalent(kind).to_string(),
            Some(format!(
                "STL {kind} ({} suggested)",
                field.field_type.c_type()
            )),
        ),
        None => (map_c_type(field.field_type.c_type()), None),
    }
}

/// The `_pad_{offset}: [u8; n]` field that keeps a gap in the recovered
/// layout visible in the declaration.
fn push_padding(out: &mut String, offset: u64, gap: u64) {
    out.push_str(&format!("    _pad_{offset}: [u8; {gap}],\n"));
}

/// Map a decompiler/C type name to its Rust shape: primitives through the
/// table, `T[N]` to an array, `T *` to a raw pointer; anything else is a
/// type reference kept as a sanitized identifier.
fn map_c_type(name: &str) -> String {
    let name = name.trim();
    if let Some(base) = name.strip_suffix('*') {
        let base = base.trim();
        let mapped = map_c_type(base);
        return if mapped == "c_void" {
            "*mut c_void".to_string()
        } else {
            format!("*mut {mapped}")
        };
    }
    if let Some(open) = name.rfind('[').filter(|_| name.ends_with(']')) {
        let len = &name[open + 1..name.len() - 1];
        if !len.is_empty() && len.chars().all(|c| c.is_ascii_digit()) {
            return format!("[{}; {len}]", map_c_type(&name[..open]));
        }
    }
    if let Some((_, rust)) = PRIMITIVES.iter().find(|(c, _)| *c == name) {
        return (*rust).to_string();
    }
    sanitize_type_name(name)
}

/// Sanitize a type or enum-member name into a valid Rust identifier:
/// non-identifier characters become `_` (runs collapsed), a leading digit
/// is prefixed, a Rust keyword gains a trailing `_`, and a name left with
/// nothing falls back to `Anonymous`.
fn sanitize_type_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_end_matches('_').to_string();
    if out.is_empty() {
        return "Anonymous".to_string();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("_{out}");
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        return format!("{out}_");
    }
    out
}

/// Sanitize a field name to snake_case: camelCase boundaries gain `_`,
/// non-identifier characters become `_`, and a Rust keyword gains a
/// trailing `_` so the declaration stays valid.
fn sanitize_field_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() {
            let boundary = match i.checked_sub(1).map(|j| chars[j]) {
                None => false,
                Some(prev) if !prev.is_ascii_alphanumeric() => false,
                Some(prev) if prev.is_ascii_uppercase() => {
                    chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase())
                }
                Some(_) => true,
            };
            if boundary {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else if c.is_ascii_alphanumeric() || *c == '_' {
            out.push(*c);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_end_matches('_').to_string();
    let out = if out.is_empty() {
        "field".to_string()
    } else if out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{out}")
    } else {
        out
    };
    if RUST_KEYWORDS.contains(&out.as_str()) {
        return format!("{out}_");
    }
    out
}

/// The first free name: Ghidra's `(unnamed)` fields repeat and two
/// categories can hold the same type name, so a collision gains `_2`,
/// `_3`, … in render order — deterministic, so re-renders never churn.
fn unique_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_string()) {
        return base.to_string();
    }
    let mut nth = 2;
    loop {
        let candidate = format!("{base}_{nth}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        nth += 1;
    }
}

/// One `pub name: type,` field line, with its trailing comment when the
/// field carries a note.
fn push_field(out: &mut String, name: &str, ty: &str, comment: Option<&str>) {
    match comment {
        Some(note) => out.push_str(&format!("    pub {name}: {ty}, // {note}\n")),
        None => out.push_str(&format!("    pub {name}: {ty},\n")),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EnumMember, FieldType, InferredField, NameOrigin, ScanMetadata};
    use calxgloss_types::Confidence;

    fn metadata() -> ScanMetadata {
        ScanMetadata::new("eqmain.dll")
    }

    fn field(name: &str, offset: u64, size: u64, type_name: &str) -> StructField {
        StructField {
            name: name.to_string(),
            offset,
            size,
            type_name: type_name.to_string(),
            linked_type: None,
            linked_kind: None,
        }
    }

    fn struct_type(name: &str, size: u64, fields: Vec<StructField>) -> NamedType {
        NamedType {
            name: name.to_string(),
            kind: TypeKind::Struct,
            category: "pe".to_string(),
            path: format!("/pe/{name}"),
            size: Some(size),
            alignment: Some(4),
            fields,
            members: Vec::new(),
            stl_kind: None,
        }
    }

    #[test]
    fn a_struct_renders_repr_c_with_padding_for_the_offset_gaps() {
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![struct_type(
                "IMAGE_DOS_HEADER",
                128,
                vec![
                    field("e_magic", 0, 2, "char[2]"),
                    field("e_lfanew", 60, 4, "dword"),
                ],
            )],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(
            rendered.contains("#[repr(C)]\npub struct IMAGE_DOS_HEADER {"),
            "{rendered}"
        );
        assert!(rendered.contains("pub e_magic: [i8; 2],"), "{rendered}");
        assert!(
            rendered.contains("_pad_2: [u8; 58],"),
            "the gap between e_magic and e_lfanew is explicit: {rendered}"
        );
        assert!(rendered.contains("pub e_lfanew: u32,"), "{rendered}");
        assert!(
            rendered.contains("_pad_64: [u8; 64],"),
            "the tail up to the declared size is explicit: {rendered}"
        );
    }

    #[test]
    fn an_enum_renders_repr_i64_with_its_member_values() {
        let disposition = NamedType {
            name: "_EXCEPTION_DISPOSITION".to_string(),
            kind: TypeKind::Enum,
            category: "excpt.h".to_string(),
            path: "/excpt.h/_EXCEPTION_DISPOSITION".to_string(),
            size: Some(4),
            alignment: None,
            fields: Vec::new(),
            members: vec![
                EnumMember {
                    name: "ExceptionContinueExecution".to_string(),
                    value: 0,
                },
                EnumMember {
                    name: "ExceptionContinueSearch".to_string(),
                    value: -1,
                },
            ],
            stl_kind: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![disposition],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(
            rendered.contains("#[repr(i64)]\npub enum _EXCEPTION_DISPOSITION {"),
            "{rendered}"
        );
        assert!(
            rendered.contains("ExceptionContinueExecution = 0,"),
            "{rendered}"
        );
        assert!(
            rendered.contains("ExceptionContinueSearch = -1,"),
            "values stay signed: {rendered}"
        );
    }

    #[test]
    fn a_nested_field_references_the_inner_type_s_declared_name() {
        let modes = NamedType {
            name: "MODES".to_string(),
            kind: TypeKind::Enum,
            category: "excpt.h".to_string(),
            path: "/excpt.h/MODES".to_string(),
            size: Some(4),
            alignment: None,
            fields: Vec::new(),
            members: vec![EnumMember {
                name: "MODE_ON".to_string(),
                value: 1,
            }],
            stl_kind: None,
        };
        let mut widget = struct_type(
            "WIDGET",
            8,
            vec![field("mode", 0, 4, "MODES"), field("raw", 4, 4, "dword")],
        );
        widget.fields[0].linked_type = Some("/excpt.h/MODES".to_string());
        widget.fields[0].linked_kind = Some(TypeKind::Enum);

        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![modes, widget],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub mode: MODES,"), "{rendered}");
        assert!(rendered.contains("pub raw: u32,"), "{rendered}");
    }

    #[test]
    fn an_stl_flagged_type_renders_as_a_rust_equivalent_comment() {
        let mut basic_string = struct_type("basic_string", 24, vec![field("ptr", 0, 8, "pointer")]);
        basic_string.stl_kind = Some(StlKind::String);
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![basic_string],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(
            rendered
                .contains("// basic_string — STL string: maps to Rust String; no layout emitted."),
            "{rendered}"
        );
        assert!(
            !rendered.contains("struct basic_string"),
            "no hand-rolled layout: {rendered}"
        );
    }

    #[test]
    fn a_field_linked_to_an_stl_type_names_the_rust_equivalent() {
        let mut basic_string = struct_type("basic_string", 24, vec![field("ptr", 0, 8, "pointer")]);
        basic_string.stl_kind = Some(StlKind::String);
        let mut holder = struct_type("HOLDER", 8, vec![field("text", 0, 24, "basic_string")]);
        holder.fields[0].linked_type = Some("/pe/basic_string".to_string());
        holder.fields[0].linked_kind = Some(TypeKind::Struct);

        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![basic_string, holder],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(
            rendered.contains("pub text: String, // STL string /pe/basic_string"),
            "{rendered}"
        );
    }

    #[test]
    fn a_type_without_a_layout_is_skipped_entirely() {
        let listing_only = NamedType {
            name: "MY_UNION".to_string(),
            kind: TypeKind::Union,
            category: "sys".to_string(),
            path: "/sys/MY_UNION".to_string(),
            size: Some(8),
            alignment: None,
            fields: Vec::new(),
            members: Vec::new(),
            stl_kind: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![listing_only],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(
            !rendered.contains("MY_UNION"),
            "a layout-less type has nothing to declare: {rendered}"
        );
    }

    #[test]
    fn field_names_are_sanitized_to_snake_case_and_stay_valid_identifiers() {
        let widget = struct_type(
            "WIDGET",
            16,
            vec![
                field("m_pData", 0, 4, "dword"),
                field("type", 4, 4, "dword"),
                field("(unnamed)", 8, 4, "dword"),
                field("(unnamed)", 12, 4, "dword"),
            ],
        );
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![widget],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub m_p_data: u32,"), "{rendered}");
        assert!(
            rendered.contains("pub type_: u32,"),
            "a keyword gains a trailing underscore: {rendered}"
        );
        assert!(rendered.contains("pub _unnamed: u32,"), "{rendered}");
        assert!(
            rendered.contains("pub _unnamed_2: u32,"),
            "repeated unnamed fields stay distinct: {rendered}"
        );
    }

    #[test]
    fn an_enum_member_spelling_a_rust_keyword_gains_a_trailing_underscore() {
        let flag = NamedType {
            name: "FLAGS".to_string(),
            kind: TypeKind::Enum,
            category: "sys".to_string(),
            path: "/sys/FLAGS".to_string(),
            size: Some(4),
            alignment: None,
            fields: Vec::new(),
            members: vec![
                EnumMember {
                    name: "type".to_string(),
                    value: 1,
                },
                EnumMember {
                    name: "match".to_string(),
                    value: 2,
                },
            ],
            stl_kind: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![flag],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("type_ = 1,"), "{rendered}");
        assert!(rendered.contains("match_ = 2,"), "{rendered}");
    }

    #[test]
    fn a_field_linked_to_a_skipped_type_still_names_its_reference() {
        // ADR-0013's accepted tradeoff: the link survives even when the
        // inner type was skipped (no layout), so the reader sees the
        // relationship and can chase it in the database.
        let mut holder = struct_type("HOLDER", 8, vec![field("twin", 0, 8, "GHOST")]);
        holder.fields[0].linked_type = Some("/sys/GHOST".to_string());
        holder.fields[0].linked_kind = Some(TypeKind::Union);

        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![holder],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub twin: GHOST,"), "{rendered}");
    }

    #[test]
    fn a_candidate_with_unplaced_fields_lays_its_fields_out_bare() {
        // Offsets are estimates: with any field unplaced, gaps are not
        // trustworthy, so no padding is claimed.
        let candidate = InferredStruct {
            name: "PLAYER".to_string(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".to_string(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x=1".to_string(),
                    source_address: 0x1801_29350,
                    stl_kind: None,
                },
                InferredField {
                    name: "y".to_string(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: None,
                    source_value: "player.y=2".to_string(),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(40),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: Vec::new(),
            vtables: Vec::new(),
            inferred_structs: vec![candidate],
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub x: i32,"), "{rendered}");
        assert!(rendered.contains("pub y: i32,"), "{rendered}");
        assert!(
            !rendered.contains("_pad_"),
            "no padding is claimed when offsets are estimates: {rendered}"
        );
    }

    #[test]
    fn pointer_and_array_types_map_to_rust_shapes() {
        let holder = struct_type(
            "HOLDER",
            24,
            vec![
                field("bytes", 0, 2, "char[2]"),
                field("table", 8, 8, "dword *"),
                field("any", 16, 8, "pointer"),
            ],
        );
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![holder],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub bytes: [i8; 2],"), "{rendered}");
        assert!(rendered.contains("pub table: *mut u32,"), "{rendered}");
        assert!(rendered.contains("pub any: *mut c_void,"), "{rendered}");
    }

    #[test]
    fn types_sharing_a_name_across_categories_get_distinct_declarations() {
        let first = struct_type("SHARED", 4, vec![field("a", 0, 4, "dword")]);
        let mut second = struct_type("SHARED", 4, vec![field("b", 0, 4, "dword")]);
        second.category = "other".to_string();
        second.path = "/other/SHARED".to_string();
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![first, second],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        let rendered = render_rust_decls(&db);
        assert!(rendered.contains("pub struct SHARED {"), "{rendered}");
        assert!(rendered.contains("pub struct SHARED_2 {"), "{rendered}");
    }

    #[test]
    fn an_inferred_candidate_renders_with_its_suggested_types() {
        let candidate = InferredStruct {
            name: "Player".to_string(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".to_string(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x=1".to_string(),
                    source_address: 0x1801_29350,
                    stl_kind: None,
                },
                InferredField {
                    name: "name".to_string(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(8),
                    source_value: "player.name=hello".to_string(),
                    source_address: 0x1801_29370,
                    stl_kind: Some(StlKind::String),
                },
            ],
            confidence: Confidence::new(60),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: Vec::new(),
            vtables: Vec::new(),
            inferred_structs: vec![candidate],
        };

        let rendered = render_rust_decls(&db);
        assert!(
            rendered.contains("#[repr(C)]\npub struct Player {"),
            "{rendered}"
        );
        assert!(rendered.contains("pub x: i32,"), "{rendered}");
        assert!(
            rendered.contains("pub name: String, // STL string (char * suggested)"),
            "a flagged field names its family: {rendered}"
        );
    }

    #[test]
    fn two_renders_of_the_same_database_are_byte_identical() {
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![struct_type(
                "IMAGE_DOS_HEADER",
                128,
                vec![field("e_magic", 0, 2, "char[2]")],
            )],
            vtables: Vec::new(),
            inferred_structs: Vec::new(),
        };

        assert_eq!(render_rust_decls(&db), render_rust_decls(&db));
    }

    #[test]
    fn sanitizers_refuse_invalid_identifiers() {
        assert_eq!(sanitize_type_name("vector<CWidget>"), "vector_CWidget");
        assert_eq!(sanitize_type_name("std::less"), "std_less");
        assert_eq!(sanitize_type_name("2bytes"), "_2bytes");
        assert_eq!(sanitize_type_name("type"), "type_");
        assert_eq!(sanitize_field_name("m_pData"), "m_p_data");
        assert_eq!(sanitize_field_name("HTTPServer"), "http_server");
        assert_eq!(sanitize_field_name("e_lfanew"), "e_lfanew");
        assert_eq!(sanitize_field_name("match"), "match_");
        assert_eq!(map_c_type("dword"), "u32");
        assert_eq!(map_c_type("undefined3"), "[u8; 3]");
        assert_eq!(map_c_type("void *"), "*mut c_void");
    }

    #[test]
    fn a_small_database_renders_the_whole_file_verbatim() {
        // The golden render: header, struct with padding and a linked
        // field, enum, STL comment, and inferred candidate — pinned
        // byte for byte so any formatting change shows up as a diff.
        let mut dos = struct_type(
            "IMAGE_DOS_HEADER",
            64,
            vec![
                field("e_magic", 0, 2, "char[2]"),
                field("e_cblp", 2, 2, "word"),
                field("m_pMode", 8, 4, "MODES"),
                field("type", 12, 8, "pointer"),
            ],
        );
        dos.fields[2].linked_type = Some("/excpt.h/MODES".to_string());
        dos.fields[2].linked_kind = Some(TypeKind::Enum);
        let modes = NamedType {
            name: "MODES".to_string(),
            kind: TypeKind::Enum,
            category: "excpt.h".to_string(),
            path: "/excpt.h/MODES".to_string(),
            size: Some(4),
            alignment: None,
            fields: Vec::new(),
            members: vec![
                EnumMember {
                    name: "MODE_ON".to_string(),
                    value: 1,
                },
                EnumMember {
                    name: "MODE_OFF".to_string(),
                    value: 2,
                },
            ],
            stl_kind: None,
        };
        let mut basic_string = struct_type("basic_string", 24, vec![field("ptr", 0, 8, "pointer")]);
        basic_string.stl_kind = Some(StlKind::String);
        let candidate = InferredStruct {
            name: "Player".to_string(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".to_string(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x=1".to_string(),
                    source_address: 0x1801_29350,
                    stl_kind: None,
                },
                InferredField {
                    name: "name".to_string(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: Some(8),
                    source_value: "player.name=hi".to_string(),
                    source_address: 0x1801_29370,
                    stl_kind: Some(StlKind::String),
                },
            ],
            confidence: Confidence::new(60),
            referenced_by: Vec::new(),
            linked_vtable: None,
            merged_from: None,
        };
        let db = TypeDatabase {
            metadata: metadata(),
            named_types: vec![dos, modes, basic_string],
            vtables: Vec::new(),
            inferred_structs: vec![candidate],
        };

        let expected = "\
// Rust declarations recovered from eqmain.dll by `calxgloss typesdb`.
// Derived artifact: regenerated from the type database on every
// scan — edit the database, never this file.

#![allow(dead_code, unused_imports)]

use core::ffi::c_void;

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: [i8; 2],
    pub e_cblp: u16,
    _pad_4: [u8; 4],
    pub m_p_mode: MODES,
    pub type_: *mut c_void,
    _pad_20: [u8; 44],
}

#[repr(i64)]
pub enum MODES {
    MODE_ON = 1,
    MODE_OFF = 2,
}

// basic_string — STL string: maps to Rust String; no layout emitted.

// Inferred candidate — confidence 60; a hypothesis from
// string literals, not a layout read from the program.
#[repr(C)]
pub struct Player {
    pub x: i32,
    _pad_4: [u8; 4],
    pub name: String, // STL string (char * suggested)
}
";
        assert_eq!(render_rust_decls(&db), expected);
    }
}
