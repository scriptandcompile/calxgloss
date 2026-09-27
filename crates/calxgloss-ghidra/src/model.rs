//! Domain types parsed out of GhidraMCP's plain-text responses.
//!
//! The server answers in `text/plain` with one record per line, so these types
//! exist to give that text a shape. Each parser lives next to the type it
//! produces and is written against the exact formats the server emits.

use std::fmt;

/// A function found by a listing or search.
///
/// Two endpoints render the same pair in different separators, so both are
/// accepted: `/list_functions` writes `name at addr` while `/searchFunctions`
/// writes `name @ addr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSummary {
    /// The Ghidra function name, e.g. `FUN_18008ed50`.
    pub name: String,
    /// Entry point virtual address.
    pub address: u64,
}

impl fmt::Display for FunctionSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {:#x}", self.name, self.address)
    }
}

/// Entry point and body range of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBody {
    /// The function's Ghidra name.
    pub name: String,
    /// First address of the function.
    pub entry: u64,
    /// First address after the function.
    pub end: u64,
}

impl FunctionBody {
    /// Size of the function in bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.entry)
    }

    /// Whether the function contains no instructions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A cross-reference between two addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    /// The address the reference runs between.
    pub address: u64,
    /// The name of the function on the referring side, when the server named
    /// one. Absent for references with no enclosing function.
    pub function: Option<String>,
    /// The reference type as Ghidra labels it, e.g. `UNCONDITIONAL_CALL`.
    pub kind: Option<String>,
}

impl Xref {
    /// A one-line rendering matching the server's own format.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The symbol name. Import-only names arrive as `Ordinal_N` when the
    /// module imports by ordinal, which carries no name to recover.
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

/// A memory region of the loaded program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment name as Ghidra labels it, e.g. `.text`.
    pub name: String,
    /// First mapped address.
    pub start: u64,
    /// One past the last mapped address.
    pub end: u64,
}

impl Segment {
    /// Size of the segment in bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the segment covers no memory.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A defined string literal and where it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteral {
    /// Address of the string.
    pub address: u64,
    /// The string's contents, with the server's surrounding quotes removed.
    pub value: String,
}

/// A decompiled function: the pseudo-C body plus the signature Ghidra inferred.
///
/// The signature is taken from the body because it is the only place Ghidra
/// reports real parameter types. The `Signature:` line of
/// `get_function_by_address` reads `undefined name(void)` for a function that
/// actually takes arguments, so it cannot be used to recover one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompiledFunction {
    /// The function's Ghidra name.
    pub name: String,
    /// The inferred signature line, e.g.
    /// `longlong FUN_18008ed50(longlong param_1,int param_2)`.
    pub signature: String,
    /// The pseudo-C body.
    pub body: String,
}

impl DecompiledFunction {
    /// The parameter names in declaration order, as Ghidra numbers them
    /// (`param_1`, `param_2`, …).
    ///
    /// Test generation needs the names because it keys test-case inputs by
    /// parameter name, so a name the server uses here has to match the one the
    /// signature carries.
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

/// Everything the client can assemble about one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionReport {
    /// The function's Ghidra name.
    pub name: String,
    /// Entry point virtual address.
    pub address: u64,
    /// Decompiled pseudo-C, with its inferred signature.
    pub decompiled: DecompiledFunction,
    /// Raw disassembly listing, one instruction per line.
    pub disassembly: String,
    /// Entry and body range.
    pub body: Option<FunctionBody>,
    /// Functions that call this one.
    pub callers: Vec<String>,
    /// Functions this one calls.
    pub callees: Vec<String>,
}

impl FunctionReport {
    /// The inferred signature, for handing to signature parsers.
    pub fn signature(&self) -> &str {
        &self.decompiled.signature
    }
}
