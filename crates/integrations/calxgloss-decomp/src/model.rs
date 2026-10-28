//! Domain types carried by the seam's answers — the record shapes the
//! analysis engine fills and the persisted records keep (issue #214).
//!
//! The Ghidra-shaped spellings these names describe (`FUN_…` names, Ghidra's
//! type vocabulary, the decompiler's signature line) are the dialect the Kuna
//! analysis engine reproduces and the pipeline's text handling reads.

use std::fmt;

/// A function found by a listing or search.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionSummary {
    /// The decompiler function name, e.g. `FUN_18008ed50`.
    pub name: String,
    /// Entry point virtual address.
    pub address: u64,
}

impl fmt::Display for FunctionSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {:#x}", self.name, self.address)
    }
}

/// A cross-reference between two addresses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Xref {
    /// The address where the reference occurs.
    pub address: u64,
    /// The name of the function on the referring side, when the analysis
    /// engine named one. Absent for references with no enclosing function.
    pub function: Option<String>,
    /// The reference type as Ghidra labels it, e.g. `UNCONDITIONAL_CALL`.
    pub kind: Option<String>,
}

impl Xref {
    /// A one-line rendering in the decompiler listing's own shape.
    pub fn to_line(&self) -> String {
        let mut line = format!("{:#x}", self.address);
        if let Some(f) = &self.function {
            line.push_str(&format!(" in {f}"));
        }
        if let Some(k) = &self.kind {
            line.push_str(&format!(" [{k}]"));
        }
        line
    }
}

/// A named program symbol — an export, an import, or a plain symbol.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    /// The symbol name. Import-only names arrive as `Ordinal_N` when the
    /// module imports by ordinal; an ordinal import carries no name to
    /// recover.
    pub name: String,
    /// The address the symbol points at, or the external slot address for an
    /// import that resolves outside the image.
    pub address: u64,
    /// Whether this symbol is an import, whose address is a placeholder slot
    /// rather than a location in the program.
    pub imported: bool,
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {:#x}", self.name, self.address)
    }
}

/// A defined string literal and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StringLiteral {
    /// Address of the string.
    pub address: u64,
    /// The string's contents, with surrounding quotes removed.
    pub value: String,
}

/// A decompiled function: the pseudo-C body plus the signature the decompiler
/// inferred.
///
/// The signature is taken from the body because it is the only place the
/// analysis engine reports real parameter types. The metadata's own signature
/// line reads `undefined name(void)` for a function that actually takes
/// arguments, so it cannot be used to recover one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecompiledFunction {
    /// The function's decompiler name.
    pub name: String,
    /// The inferred signature line, e.g.
    /// `longlong FUN_18008ed50(longlong param_1,int param_2)`.
    pub signature: String,
    /// The pseudo-C body.
    pub body: String,
}

impl DecompiledFunction {
    /// The parameter names in declaration order, as the decompiler numbers
    /// them (`param_1`, `param_2`, …).
    ///
    /// Test generation needs the names because it keys test-case inputs by
    /// parameter name, so a name the analysis engine uses here has to match
    /// the one the signature carries.
    pub fn parameter_names(&self) -> Vec<String> {
        let Some(open) = self.signature.find('(') else {
            return Vec::new();
        };
        let Some(close) = self.signature.rfind(')') else {
            return Vec::new();
        };
        let inner = &self.signature[open + 1..close];
        // A function taking nothing is written `(void)`, not `()`. Reading that
        // as a parameter would invent a parameter named `void`.
        if inner.trim().is_empty() || inner.trim() == "void" {
            return Vec::new();
        }
        inner
            .split(',')
            .filter_map(|p| {
                // Each parameter is `type name`, with indirection attached to
                // the name: `char *param_3`. So the name is the last token,
                // stripped of its leading `*`.
                let token = p.split_whitespace().next_back()?;
                let name: String = token
                    .trim_start_matches('*')
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty()).then_some(name)
            })
            .collect()
    }
}

/// A named type in the Type Manager, as the `data_types()` answer renders it.
///
/// The Type Manager holds every type the analysis engine knows about,
/// including types never applied to a symbol. That is what makes this
/// listing the source for named-type recovery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DataTypeEntry {
    /// The type name, e.g. `_EXCEPTION_DISPOSITION`. Pointer variants arrive
    /// as separate entries (`name *`).
    pub name: String,
    /// The category the type sits in, e.g. `excpt.h`.
    pub category: String,
    /// Size in bytes. `None` when the analysis engine reports the size as
    /// `variable`.
    pub size: Option<u64>,
    /// Full path through the Type Manager, e.g. `/excpt.h/_EXCEPTION_DISPOSITION`.
    pub path: String,
}

/// A defined data object in the listing, as the `data_items()` answer does.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DataItem {
    /// The label the analysis engine shows, e.g. `IMAGE_DOS_HEADER_180000000`,
    /// or a generated `DAT_...` name when the object carries no label.
    pub label: String,
    /// Address of the object.
    pub address: u64,
    /// The applied data type name, e.g. `IMAGE_DOS_HEADER`.
    pub type_name: String,
    /// Size in bytes.
    pub length: u64,
}

impl fmt::Display for DataItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:x} [{}] ({} bytes)",
            self.label, self.address, self.type_name, self.length
        )
    }
}

/// One field of a structure layout.
///
/// Wire shape for the `struct_layout()` answer only. The persisted recovered
/// shape is `calxgloss-typesdb`'s `StructField`; the two stay deliberately
/// split (wire vs. persisted ownership) and are mapped by its
/// `From<&StructFieldLayout>` impl — the only place the shapes meet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StructFieldLayout {
    /// Byte offset of the field from the start of the structure.
    pub offset: u64,
    /// Size of the field in bytes.
    pub size: u64,
    /// The field's data type name, e.g. `dword` or `char[2]`.
    pub type_name: String,
    /// Field name; the analysis engine writes `(unnamed)` for anonymous
    /// fields.
    pub field_name: String,
}

/// A structure's full field layout, as the `struct_layout()` answer renders it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StructLayout {
    /// The structure name.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub alignment: u64,
    /// Defined fields, in offset order.
    pub fields: Vec<StructFieldLayout>,
}

/// One member of an enumeration.
///
/// Wire shape for the `enum_values()` answer only. The persisted recovered
/// shape is `calxgloss-typesdb`'s `EnumMember`; the records are identical but
/// stay split on purpose, mapped by its `From<&EnumMember>` impl.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnumMember {
    /// Member name, e.g. `ExceptionContinueExecution`.
    pub name: String,
    /// Member value; signed because the analysis engine's enums may hold
    /// negative values.
    pub value: i64,
}

/// An enumeration and its members, as the `enum_values()` answer renders it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnumDefinition {
    /// The enumeration name.
    pub name: String,
    /// Storage size in bytes.
    pub size: u64,
    /// The members.
    pub members: Vec<EnumMember>,
}

/// Convert a program virtual address into a file-relative one.
///
/// The image base is the program's lowest mapped address. Subtracting it
/// yields the RVA that the PE headers index exports and imports by.
pub fn rva_from_va(image_base: u64, va: u64) -> Option<u32> {
    let rva = va.checked_sub(image_base)?;
    u32::try_from(rva).ok()
}

#[cfg(test)]
mod tests {
    use super::rva_from_va;

    #[test]
    fn rva_from_va_subtracts_the_image_base() {
        assert_eq!(rva_from_va(0x180000000, 0x18008ed50), Some(0x8ed50));
        // A VA below the image base is not addressable, and silently wrapping
        // would produce a plausible-looking but wrong RVA.
        assert_eq!(rva_from_va(0x180000000, 0x17ffffff), None);
    }
}
