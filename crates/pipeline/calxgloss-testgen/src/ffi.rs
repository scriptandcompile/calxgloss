//! FFI stub generation for linking against original DLLs.
//!
//! This module provides functionality to parse Windows function signatures
//! and generate Rust `extern "C"` blocks that can be used to call the
//! original (untranslated) functions via FFI.
//!
//! # Type Mappings
//!
//! Windows types are mapped to their Rust equivalents:
//!
//! | Windows Type | Rust Type |
//! |-------------|-----------|
//! | `void` | `()` |
//! | `int`, `long`, `INT32`, `LONG` | `i32` |
//! | `short`, `INT16`, `WORD` | `i16` |
//! | `char`, `INT8`, `BYTE` | `i8` |
//! | `long long`, `INT64`, `LONGLONG` | `i64` |
//! | `unsigned int`, `UINT`, `DWORD` | `u32` |
//! | `unsigned short`, `USHORT`, `WORD` | `u16` |
//! | `unsigned char`, `UCHAR`, `BYTE` | `u8` |
//! | `unsigned long long`, `ULONG64`, `ULONGLONG` | `u64` |
//! | `bool`, `BOOL` | `bool` |
//! | `float` | `f32` |
//! | `double` | `f64` |
//! | `float*`, `double*` | `*mut f32`, `*mut f64` |
//! | `char*`, `const char*`, `LPSTR`, `LPCSTR` | `*mut i8`, `*const i8` |
//! | `wchar_t*`, `LPCWSTR`, `LPWSTR` | `*const u16`, `*mut u16` |
//! | `void*`, `LPVOID`, `PVOID` | `*mut u8` |
//! | `HMODULE`, `HANDLE`, `HINSTANCE`, `HWND`, `HDC`, etc. | `*mut u8` |
//! | `size_t` | `usize` |
//! | `ptrdiff_t` | `isize` |

use std::collections::HashMap;

use anyhow::Result;
use tracing::debug;

/// Type information for a function parameter.
///
/// Contains metadata about a parameter's type, whether it's a pointer,
/// whether it's signed, and its bit width (if known).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterTypeInfo {
    /// Parameter name (if available).
    pub name: Option<String>,

    /// The parameter type string (e.g., `"int"`, `"char*"`).
    pub r#type: String,

    /// Whether this is a pointer type.
    pub is_pointer: bool,

    /// Whether this is a signed type.
    pub is_signed: bool,

    /// Bit width of the type, if known.
    pub bit_width: Option<u32>,
}

/// A parsed function signature.
///
/// Contains the return type, calling convention, parameter list, and
/// optional return type information for code generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignature {
    /// The return type (e.g., `"int"`, `"void"`, `"BOOL"`).
    pub return_type: String,

    /// The calling convention (e.g., `"__stdcall"`, `"__cdecl"`).
    pub calling_convention: Option<String>,

    /// The function parameters.
    pub parameters: Vec<ParameterTypeInfo>,

    /// A map of Windows type names to Rust types for reference.
    pub type_map: HashMap<String, String>,
}

/// A generated FFI stub.
///
/// Contains the raw Rust code for the `extern "C"` block along with
/// parsed type information for downstream use.
#[derive(Debug, Clone)]
pub struct FfiStub {
    /// The generated Rust FFI code.
    pub code: String,

    /// The DLL this stub targets.
    pub dll: String,

    /// The function name.
    pub function: String,

    /// The parsed signature information.
    pub signature: ParsedSignature,
}

/// Windows type to Rust type mappings.
///
/// Maps common Windows API type names to their Rust equivalents.
const TYPE_MAP: &[(&str, &str, bool, bool, Option<u32>)] = &[
    // Integer types
    ("int", "i32", true, false, Some(32)),
    ("long", "i32", true, false, Some(32)),
    ("short", "i16", true, false, Some(16)),
    ("char", "i8", true, false, Some(8)),
    ("long long", "i64", true, false, Some(64)),
    ("INT8", "i8", true, false, Some(8)),
    ("INT16", "i16", true, false, Some(16)),
    ("INT32", "i32", true, false, Some(32)),
    ("INT64", "i64", true, false, Some(64)),
    ("INTEGER", "i32", true, false, Some(32)),
    // Unsigned integer types
    ("unsigned int", "u32", false, false, Some(32)),
    ("unsigned short", "u16", false, false, Some(16)),
    ("unsigned char", "u8", false, false, Some(8)),
    ("unsigned long long", "u64", false, false, Some(64)),
    ("UINT8", "u8", false, false, Some(8)),
    ("UINT16", "u16", false, false, Some(16)),
    ("UINT32", "u32", false, false, Some(32)),
    ("UINT64", "u64", false, false, Some(64)),
    ("UINT", "u32", false, false, Some(32)),
    ("ULONG", "u32", false, false, Some(32)),
    ("USHORT", "u16", false, false, Some(16)),
    ("UCHAR", "u8", false, false, Some(8)),
    ("DWORD", "u32", false, false, Some(32)),
    ("WORD", "u16", false, false, Some(16)),
    ("BYTE", "u8", false, false, Some(8)),
    // Boolean types
    ("bool", "bool", false, false, None),
    ("BOOL", "bool", false, false, None),
    // Floating point types
    ("float", "f32", false, false, None),
    ("double", "f64", false, false, None),
    // Pointer types
    ("void", "()", false, false, None),
    ("size_t", "usize", false, false, None),
    ("ptrdiff_t", "isize", true, false, None),
    ("HRESULT", "i32", true, false, Some(32)),
    ("BOOL32", "i32", true, false, Some(32)),
];

/// Parse a Windows function signature into its components.
///
/// # Arguments
///
/// * `signature` - A function signature string, e.g.
///   `"int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"`
///
/// # Returns
///
/// A [`ParsedSignature`] with the return type, calling convention, and parameters,
/// or an error if the signature cannot be parsed.
pub fn parse_signature(signature: &str) -> Result<ParsedSignature> {
    debug!(signature, "Parsing signature");

    let sig = signature.trim();
    let mut type_map = HashMap::new();
    for (win_type, rust_type, _signed, _is_unsigned, _bits) in TYPE_MAP.iter() {
        type_map.insert(win_type.to_string(), rust_type.to_string());
        if let Some(_b) = _bits {
            type_map.insert(format!("{}bit", win_type), rust_type.to_string());
            type_map.insert(format!("{}-bit", win_type), rust_type.to_string());
        }
    }

    // First, extract the parameter string between parentheses
    let params_str = extract_params_str(sig)?;

    // The part before the opening paren is "return_type calling_convention function_name"
    let before_paren = &sig[..sig.find('(').unwrap_or(sig.len())];
    let before_paren = before_paren.trim();

    // Extract calling convention and the rest
    let (rest, calling_convention) = extract_calling_convention(before_paren);

    // Now `rest` contains "return_type function_name"
    // Split this into return_type and function_name
    let return_type = extract_return_type_from_rest(rest);

    // Parse parameters
    let parameters = parse_parameters(params_str, &type_map)?;

    let parsed = ParsedSignature {
        return_type,
        calling_convention,
        parameters,
        type_map,
    };

    debug!(
        return_type = %parsed.return_type,
        params = parsed.parameters.len(),
        "Parsed signature"
    );

    Ok(parsed)
}

/// Extract just the parameter string between parentheses.
fn extract_params_str(sig: &str) -> Result<&str> {
    let open_paren = sig
        .find('(')
        .ok_or_else(|| anyhow::anyhow!("No opening parenthesis found in signature"))?;
    let close_paren = sig
        .find(')')
        .ok_or_else(|| anyhow::anyhow!("No closing parenthesis found in signature"))?;

    if close_paren <= open_paren {
        return Err(anyhow::anyhow!(
            "Parentheses are in the wrong order in signature"
        ));
    }

    Ok(&sig[open_paren + 1..close_paren])
}

/// Generate a complete FFI stub for a function.
///
/// # Arguments
///
/// * `dll` - The DLL filename.
/// * `function` - The function name.
/// * `signature` - The function signature string.
///
/// # Returns
///
/// A [`FfiStub`] containing the generated code and parsed information.
pub fn generate_ffi_stub(dll: &str, function: &str, signature: &str) -> Result<FfiStub> {
    debug!(dll, function, "Generating FFI stub");

    let parsed = parse_signature(signature)?;

    let rust_return = windows_type_to_rust(&parsed.return_type, &parsed.type_map);
    let is_void = rust_return == "()";

    // Build the extern "C" block
    let mut code = String::new();
    code.push_str("extern \"C\" {\n");
    code.push_str(&format!("    #[link_name = \"{}\"]\n", function));
    code.push_str(&format!("    pub fn {}(", function));

    let params: Vec<String> = parsed
        .parameters
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let rust_type = windows_type_to_rust(&p.r#type, &parsed.type_map);
            let name = p
                .name
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("arg_{}", i));
            format!("{}: {}", name, rust_type)
        })
        .collect();

    code.push_str(&params.join(", "));
    code.push(')');

    if !is_void {
        code.push_str(" -> ");
        code.push_str(&rust_return);
    }

    code.push_str(";\n");
    code.push_str("}\n");

    Ok(FfiStub {
        code,
        dll: dll.to_string(),
        function: function.to_string(),
        signature: parsed,
    })
}

/// Builder for manually constructing FFI stubs.
///
/// Use this when you don't have a parsed signature string but want to
/// construct an FFI stub from component types.
///
/// # Example
///
/// ```
/// use calxgloss_testgen::FfiStubBuilder;
///
/// let stub = FfiStubBuilder::new("game.dll", "MyFunc")
///     .return_type("int")
///     .calling_convention("__stdcall")
///     .param("x", "i32")
///     .param("y", "i32")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FfiStubBuilder {
    dll: String,
    function: String,
    return_type: String,
    calling_convention: Option<String>,
    params: Vec<(String, String)>, // (name, type)
}

impl FfiStubBuilder {
    /// Create a new FFI stub builder.
    pub fn new(dll: &str, function: &str) -> Self {
        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            return_type: "void".to_string(),
            calling_convention: None,
            params: Vec::new(),
        }
    }

    /// Set the return type.
    pub fn return_type(mut self, r#type: &str) -> Self {
        self.return_type = r#type.to_string();
        self
    }

    /// Set the calling convention.
    pub fn calling_convention(mut self, convention: &str) -> Self {
        self.calling_convention = Some(convention.to_string());
        self
    }

    /// Add a parameter.
    pub fn param(mut self, name: &str, r#type: &str) -> Self {
        self.params.push((name.to_string(), r#type.to_string()));
        self
    }

    /// Build the FFI stub.
    pub fn build(self) -> FfiStub {
        let rust_return = &self.return_type;
        let is_void = rust_return == "()";

        let mut code = String::new();
        code.push_str("extern \"C\" {\n");
        code.push_str(&format!("    #[link_name = \"{}\"]\n", self.function));
        code.push_str(&format!("    pub fn {}(", self.function));

        let params: Vec<String> = self
            .params
            .iter()
            .map(|(name, r#type)| format!("{}: {}", name, r#type))
            .collect();

        code.push_str(&params.join(", "));
        code.push(')');

        if !is_void {
            code.push_str(" -> ");
            code.push_str(rust_return);
        }

        code.push_str(";\n");
        code.push_str("}\n");

        let params_info: Vec<ParameterTypeInfo> = self
            .params
            .iter()
            .map(|(name, r#type)| ParameterTypeInfo {
                name: Some(name.clone()),
                r#type: r#type.clone(),
                is_pointer: r#type.ends_with('*'),
                is_signed: false, // Assume unsigned for manual stubs
                bit_width: None,
            })
            .collect();

        FfiStub {
            code,
            dll: self.dll,
            function: self.function,
            signature: ParsedSignature {
                return_type: self.return_type,
                calling_convention: self.calling_convention,
                parameters: params_info,
                type_map: HashMap::new(),
            },
        }
    }
}

/// Map a Ghidra decompiler type name to a Rust FFI type.
///
/// Ghidra's decompiler emits a different vocabulary from a C SDK: it writes
/// `longlong` and `ulonglong` without a space, `undefined4` instead of `int`,
/// and `pointer`/`code` for types it could not resolve. None of those are in
/// [`TYPE_MAP`], and falling through to the raw string would emit invalid Rust,
/// so they are normalised here.
///
/// Resolution order:
/// 1. An exact match in `type_map`, so SDK spellings like `DWORD` and
///    `unsigned int` keep their existing mapping.
/// 2. Ghidra's own spellings, with pointer depth preserved.
/// 3. [`windows_type_to_rust`] as a fallback.
///
/// Pointer depth is significant: `undefined **` becomes `*mut *mut u8`, not
/// `*mut u8`, because a single level would silently drop a dereference.
pub fn ghidra_type_to_rust(type_name: &str, type_map: &HashMap<String, String>) -> String {
    let trimmed = type_name.trim();
    if trimmed.is_empty() {
        return "()".to_string();
    }

    // An exact hit in the type map wins, so Windows SDK names are unaffected.
    if let Some(mapped) = type_map.get(trimmed) {
        return mapped.clone();
    }

    // Split off pointer depth: count stars, then reduce the base.
    let depth = trimmed.matches('*').count();
    let mut base = trimmed.trim();
    while let Some(rest) = base.strip_suffix('*') {
        base = rest.trim_end();
    }
    base = base.trim();
    // `const` and `unsigned` are already in the map where they matter, so a bare
    // `const` left over here is decoration rather than part of the type name.
    if let Some(rest) = base.strip_prefix("const") {
        base = rest.trim();
    }
    // Ghidra writes `unsigned long` and friends; the map keys include
    // `unsigned`, so retry the full form before reducing it.
    if let Some(mapped) = type_map.get(base) {
        return apply_pointer_depth(mapped, depth);
    }

    let scalar = match base {
        // Width-qualified unknowns. Ghidra's `undefinedN` is unsigned storage of
        // unknown interpretation, so it is mapped to the unsigned type.
        "undefined1" | "byte" | "uchar" => "u8",
        "undefined2" | "ushort" | "word" => "u16",
        "undefined4" | "uint" | "dword" => "u32",
        "undefined8" | "ulonglong" | "ulong" | "qword" => "u64",
        "undefined" | "undefined16" => "u8",

        // Signed forms, written without the space the SDK uses.
        "longlong" => "i64",
        "long" | "int" | "sint" => "i32",
        "short" => "i16",
        "char" | "schar" => "i8",

        // Ghidra uses these for types it could not resolve.
        "pointer" | "code" | "void" | "undefined_p" => "*mut u8",
        "float" => "f32",
        "double" => "f64",
        "wchar_t" => "u16",
        "bool" | "BOOL" => "i32",

        _ => {
            // Unknown: hand the original string to the Windows mapper, which
            // will pass it through unchanged. The caller validates the result.
            return windows_type_to_rust(trimmed, type_map);
        }
    };

    apply_pointer_depth(scalar, depth)
}

/// Wrap a mapped scalar in the number of pointer levels it was written with.
fn apply_pointer_depth(scalar: &str, depth: usize) -> String {
    // The Ghidra spellings above already carry their own `*` where the type is
    // itself a pointer (`pointer`, `void`), so don't double-wrap those.
    let base_pointer = scalar.starts_with('*');
    let mut out = scalar.to_string();
    for _ in 0..depth {
        if base_pointer {
            // Re-point through the pointee, e.g. `*mut u8` -> `*mut *mut u8`.
            out = format!("mut {}", out);
            out = format!("*{out}");
        } else {
            out = format!("*mut {out}");
        }
    }
    out
}

/// Map a Windows type name to a Rust type.
///
/// Handles basic type names and pointer types (e.g., `"char*"` -> `"*mut i8"`).
pub fn windows_type_to_rust(type_name: &str, type_map: &HashMap<String, String>) -> String {
    let trimmed = type_name.trim();

    // Check for pointer types
    if trimmed.ends_with('*') {
        let base = trimmed.trim_end_matches('*').trim();
        let base_rust = type_map.get(base).cloned().unwrap_or_else(|| match base {
            "char" | "i8" => "*mut i8".to_string(),
            "const char" | "LPCSTR" | "LPCWSTR" | "i16" => "*const i8".to_string(),
            "wchar_t" | "u16" => "*const u16".to_string(),
            "void" => "*mut u8".to_string(),
            _ => "*mut u8".to_string(),
        });

        if base_rust.starts_with('*') {
            // Already a pointer type, just add another level
            let is_const = base_rust.contains("const");
            if is_const {
                base_rust.clone() // Keep the existing pointer
            } else {
                // Check if we need mut vs const
                if type_name.starts_with("const ") {
                    "*const u8".to_string()
                } else {
                    "*mut u8".to_string()
                }
            }
        } else {
            if type_name.starts_with("const ") {
                format!("*const {}", base_rust)
            } else {
                format!("*mut {}", base_rust)
            }
        }
    } else {
        type_map
            .get(trimmed)
            .cloned()
            .unwrap_or_else(|| trimmed.to_string())
    }
}

/// Extract the calling convention from a signature.
/// Returns the prefix before the convention and the convention itself.
fn extract_calling_convention(sig: &str) -> (&str, Option<String>) {
    let conventions = [
        "__stdcall",
        "__cdecl",
        "__fastcall",
        "__thiscall",
        "__naked",
        "__retpoline",
    ];
    for conv in conventions {
        if let Some(pos) = sig.find(conv) {
            let before = sig[..pos].trim();
            return (before, Some(conv.to_string()));
        }
    }
    (sig, None)
}

/// Extract the return type from a "return_type function_name" string.
fn extract_return_type_from_rest(rest: &str) -> String {
    let rest = rest.trim();
    if rest.is_empty() {
        return "void".to_string();
    }

    let words: Vec<&str> = rest.split_whitespace().collect();
    if words.len() == 1 {
        // Single word: either just a type or just a name
        let known_types = [
            "int", "void", "char", "long", "short", "float", "double", "bool", "BOOL", "HRESULT",
            "UINT", "ULONG", "USHORT", "UINT32", "ULONG32", "INT32", "DWORD", "LPVOID", "HANDLE",
            "LPCSTR", "LPCWSTR", "WCHAR", "SIZE_T", "PTR",
        ];
        if known_types.iter().any(|t| t == &words[0]) {
            return words[0].to_string();
        }
        // It's likely just a function name, default to void
        return "void".to_string();
    }

    // Multiple words: first word(s) form the type, rest is the function name
    // Handle compound types like "unsigned int", "long long", "unsigned long long"
    let first = words[0].to_lowercase();
    if first == "unsigned" && words.len() >= 2 {
        return format!("unsigned {}", words[1]);
    }
    if first == "long" && words.len() >= 2 && words[1].to_lowercase() == "long" {
        return "long long".to_string();
    }
    if first == "signed" && words.len() >= 2 {
        return format!("signed {}", words[1]);
    }

    // Default: return the first word
    words[0].to_string()
}

/// Parse individual parameters from a parameter string.
fn parse_parameters(
    params_str: &str,
    type_map: &HashMap<String, String>,
) -> Result<Vec<ParameterTypeInfo>> {
    let params_str = params_str.trim();
    if params_str.is_empty() {
        return Ok(Vec::new());
    }

    let mut parameters = Vec::new();

    // Handle "void" parameter (means no parameters)
    if params_str == "void" {
        return Ok(Vec::new());
    }

    // Split by comma, but respect parentheses and brackets for complex types
    let parts = split_parameters(params_str);

    for (i, part) in parts.iter().enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let param_info = parse_single_parameter(part, i, type_map)?;
        parameters.push(param_info);
    }

    Ok(parameters)
}

/// Split a parameter string by commas, respecting parentheses and brackets.
fn split_parameters(params_str: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0;
    let mut bracket_depth = 0;

    for ch in params_str.chars() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth -= 1,
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                parts.push(current.clone());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Parse a single parameter into its type, name, and metadata.
fn parse_single_parameter(
    param: &str,
    _index: usize,
    _type_map: &HashMap<String, String>,
) -> Result<ParameterTypeInfo> {
    let param = param.trim();

    // Extract type and name
    // Format: "type name" or "type* name" or "type<something>"
    let (type_str, name_str) = extract_type_and_name(param)?;

    // Determine if it's a pointer
    let is_pointer = type_str.ends_with('*');

    // Determine if it's signed and its bit width
    let (is_signed, bit_width) = classify_type(&type_str);

    let name = if name_str.trim().is_empty() {
        None
    } else {
        Some(name_str.trim().to_string())
    };

    Ok(ParameterTypeInfo {
        name,
        r#type: type_str.to_string(),
        is_pointer,
        is_signed,
        bit_width,
    })
}

/// Extract the type string and name from a parameter string.
fn extract_type_and_name(param: &str) -> Result<(String, String)> {
    let param = param.trim();

    // Handle array parameters: "char buffer[256]"
    if let Some(bracket_pos) = param.find('[') {
        let type_and_name = &param[..bracket_pos];
        return Ok(split_type_name(type_and_name));
    }

    // Handle pointer parameters: "char* name" or "const char* name"
    if let Some(asterisk_pos) = param.rfind('*') {
        let type_part = &param[..asterisk_pos].trim();
        let rest = &param[asterisk_pos..].trim();

        // Check for name after the asterisk
        let after_asterisk = rest.trim_start_matches('*').trim();
        if !after_asterisk.is_empty() {
            // Type might have spaces: "const char * name"
            // We want everything up to the last * group, then the name
            let type_str = format!("{}*", type_part);
            let name_str = after_asterisk.to_string();
            return Ok((type_str, name_str));
        } else {
            // No name, just type*
            // Check if there's a trailing name with spaces
            let full_rest = param[asterisk_pos..].trim();
            let parts: Vec<&str> = full_rest.split_whitespace().collect();
            let type_str = format!("{}*", type_part);
            if parts.len() > 1 {
                let name_str = parts[1..].join(" ");
                return Ok((type_str, name_str));
            }
            return Ok((type_str, String::new()));
        }
    }

    // Handle "type name" format
    Ok(split_type_name(param))
}

/// Split a type string into (type, name) components.
fn split_type_name(param: &str) -> (String, String) {
    let param = param.trim();

    // Handle function pointer types: "HRESULT (WINAPI *Callback)(...)"
    if param.contains('(') && param.contains("(*") {
        // Function pointer parameter
        let parts: Vec<&str> = param.splitn(2, ' ').collect();
        if parts.len() == 2 {
            // Might have name at the end
            let type_part = parts[0];
            let name_part = parts[1];
            return (type_part.to_string(), name_part.to_string());
        }
    }

    // Handle compound types: "unsigned int", "long long", "unsigned long long"
    let compound_types = [
        "unsigned long long",
        "unsigned int",
        "long long",
        "signed int",
        "signed char",
        "signed short",
        "signed long",
    ];
    for compound in &compound_types {
        if param.starts_with(*compound) {
            let remainder = &param[compound.len()..].trim_start();
            if remainder.is_empty() {
                return (compound.to_string(), String::new());
            } else {
                // There's a name after the compound type
                return (compound.to_string(), remainder.to_string());
            }
        }
    }

    // Simple case: "type name" or just "type"
    let mut words = param.splitn(2, ' ');
    let type_part = words.next().unwrap_or(param).to_string();
    let rest = words.next().unwrap_or("").to_string();

    if rest.is_empty() || rest == "*" || rest == "* *" || rest == "*mut" {
        (type_part, String::new())
    } else {
        (type_part, rest)
    }
}

/// Classify a type as signed/unsigned and determine its bit width.
fn classify_type(type_str: &str) -> (bool, Option<u32>) {
    let t = type_str.trim();

    // Check for unsigned
    if t.contains("unsigned") || t.contains("UINT") || t.contains("ULONG") || t.contains("DWORD") {
        return (false, extract_bit_width(t));
    }

    // Check for signed or default signed types
    if t.contains("short")
        || t.contains("int")
        || t.contains("long")
        || t.contains("char")
        || t.contains("INT")
        || t.contains("LONG")
    {
        return (true, extract_bit_width(t));
    }

    // Default: signed for integer-like types
    if t.contains("bool") || t.contains("BOOL") {
        return (false, None);
    }

    // Floating point: signed (negative values are valid)
    if t.contains("float") || t.contains("double") {
        return (true, None);
    }

    // Pointer types: treat as signed (they represent addresses)
    if t.ends_with('*') {
        return (true, None);
    }

    (true, None)
}

/// Extract bit width from a type string.
fn extract_bit_width(type_str: &str) -> Option<u32> {
    let t = type_str.to_lowercase();
    if t.contains("8") && (t.contains("int") || t.contains("char") || t.contains("byte")) {
        return Some(8);
    }
    if t.contains("16") && (t.contains("int") || t.contains("short") || t.contains("word")) {
        return Some(16);
    }
    if t.contains("32") && (t.contains("int") || t.contains("long") || t.contains("dword")) {
        return Some(32);
    }
    if t.contains("64")
        && (t.contains("long long") || t.contains("int64") || t.contains("lONGLONG"))
    {
        return Some(64);
    }
    None
}
