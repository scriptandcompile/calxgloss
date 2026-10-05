//! Harness types — specs, scalars, and the function locator.

use crate::Machine;
use anyhow::{Context, Result};

use crate::ffi::{ParsedSignature, ghidra_type_to_rust};

/// How the DLL should be loaded before calling into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// Map without running `DllMain` or resolving imports.
    ///
    /// The safe default: it cannot trigger constructors in the target binary.
    NoResolve,
    /// Load fully, running `DllMain` and resolving imports.
    Full,
}

impl LoadMode {
    /// True when the harness should be told to run `DllMain`.
    pub fn runs_dll_main(self) -> bool {
        matches!(self, LoadMode::Full)
    }
}

/// How the harness locates the function inside the loaded module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionLocator {
    /// Call at `module_base + rva`. The only option for internal functions.
    Rva(u32),
    /// Resolve through `GetProcAddress` by name.
    ExportName(String),
    /// Resolve through `GetProcAddress` by ordinal.
    ExportOrdinal(u32),
}

impl FunctionLocator {
    /// The `--flag value` argument passed to the harness.
    pub fn harness_args(&self) -> Vec<String> {
        match self {
            FunctionLocator::Rva(rva) => vec!["--rva".into(), format!("0x{rva:x}")],
            FunctionLocator::ExportName(name) => vec!["--export-name".into(), name.clone()],
            FunctionLocator::ExportOrdinal(ord) => {
                vec!["--export-ordinal".into(), ord.to_string()]
            }
        }
    }
}

/// A scalar type the harness can marshal across the FFI boundary.
///
/// Structs, arrays, and unrecognised type names are deliberately unsupported:
/// marshalling them correctly is not guessable, and a wrong guess produces
/// silently incorrect baselines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    /// A pointer, carried as a `void*`.
    Ptr,
    /// No return value.
    Unit,
}

impl ScalarKind {
    /// The wire tag for this type.
    pub fn tag(self) -> &'static str {
        match self {
            ScalarKind::I8 => "i8",
            ScalarKind::I16 => "i16",
            ScalarKind::I32 => "i32",
            ScalarKind::I64 => "i64",
            ScalarKind::U8 => "u8",
            ScalarKind::U16 => "u16",
            ScalarKind::U32 => "u32",
            ScalarKind::U64 => "u64",
            ScalarKind::F32 => "f32",
            ScalarKind::F64 => "f64",
            ScalarKind::Ptr => "p",
            ScalarKind::Unit => "void",
        }
    }

    /// Classify a Rust type produced by type mapping.
    ///
    /// `machine` decides the width of `isize`/`usize`, which are pointer-sized
    /// and so differ between 32- and 64-bit targets.
    pub fn from_rust_type(rust_type: &str, machine: Machine) -> Option<Self> {
        let t = rust_type.trim();
        if t == "()" {
            return Some(ScalarKind::Unit);
        }
        // Strip mutability markers before matching, so `*mut u8` and
        // `*const u8` both collapse to "a pointer".
        if t.starts_with('*') {
            return Some(ScalarKind::Ptr);
        }
        let is_64 = machine == Machine::X86_64;
        match t {
            "i8" => Some(ScalarKind::I8),
            "i16" => Some(ScalarKind::I16),
            "i32" | "isize32" => Some(ScalarKind::I32),
            "i64" => Some(ScalarKind::I64),
            "isize" => Some(if is_64 {
                ScalarKind::I64
            } else {
                ScalarKind::I32
            }),
            "u8" => Some(ScalarKind::U8),
            "u16" => Some(ScalarKind::U16),
            "u32" | "usize32" => Some(ScalarKind::U32),
            "u64" => Some(ScalarKind::U64),
            "usize" => Some(if is_64 {
                ScalarKind::U64
            } else {
                ScalarKind::U32
            }),
            "f32" => Some(ScalarKind::F32),
            "f64" => Some(ScalarKind::F64),
            _ => None,
        }
    }
}

/// One parameter of the function under test.
#[derive(Debug, Clone)]
pub struct ParamSpec {
    /// Parameter name, as it appears in the test case's `inputs` map.
    pub name: String,
    /// How the value is marshalled.
    pub kind: ScalarKind,
    /// The Rust type used in the generated function pointer.
    pub rust_type: String,
}

/// Everything the harness generator needs.
#[derive(Debug, Clone)]
pub struct HarnessSpec {
    /// Human-readable name, used in diagnostics only.
    pub function_label: String,
    /// How to find the function in the loaded module.
    pub locator: FunctionLocator,
    /// Parameters, in call order.
    pub params: Vec<ParamSpec>,
    /// How the return value is marshalled.
    pub return_kind: ScalarKind,
    /// How the DLL should be loaded.
    pub load_mode: LoadMode,
}

impl HarnessSpec {
    /// Build a spec from a decompiled signature.
    ///
    /// `machine` is the target's architecture, which decides the width of
    /// pointer-sized integer types.
    ///
    /// Returns an error naming the offending type when a parameter or the return
    /// value is not a marshallable scalar, so the failure is actionable rather
    /// than a compile error inside generated code.
    pub fn new(
        function_label: &str,
        locator: FunctionLocator,
        signature: &ParsedSignature,
        machine: Machine,
    ) -> Result<Self> {
        let mut params = Vec::with_capacity(signature.parameters.len());
        for (i, p) in signature.parameters.iter().enumerate() {
            let rust_type = ghidra_type_to_rust(&p.r#type, &signature.type_map);
            let kind = ScalarKind::from_rust_type(&rust_type, machine).with_context(|| {
                format!(
                    "parameter {} ({}) has type '{}', which cannot be marshalled across the FFI; \
                     only scalars and pointers are supported",
                    i + 1,
                    p.name.as_deref().unwrap_or("<unnamed>"),
                    p.r#type
                )
            })?;
            params.push(ParamSpec {
                // Ghidra names parameters param_1..param_N; fall back to a
                // positional name so the inputs map is still addressable.
                name: p.name.clone().unwrap_or_else(|| format!("param_{}", i + 1)),
                kind,
                rust_type,
            });
        }

        let return_rust = ghidra_type_to_rust(&signature.return_type, &signature.type_map);
        let return_kind = ScalarKind::from_rust_type(&return_rust, machine).with_context(|| {
            format!(
                "return type '{}' cannot be marshalled across the FFI; \
                 only scalars, pointers, and void are supported",
                signature.return_type
            )
        })?;

        Ok(Self {
            function_label: function_label.to_string(),
            locator,
            params,
            return_kind,
            load_mode: LoadMode::NoResolve,
        })
    }

    /// The Rust type of the generated function pointer, e.g. `fn(i64, i32) -> i64`.
    pub fn fn_pointer_type(&self) -> String {
        let args = self
            .params
            .iter()
            .map(|p| p.rust_type.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "extern \"system\" fn({args}) -> {}",
            self.return_rust_type()
        )
    }

    /// The Rust spelling of the return type.
    pub fn return_rust_type(&self) -> String {
        match self.return_kind {
            ScalarKind::I8 => "i8",
            ScalarKind::I16 => "i16",
            ScalarKind::I32 => "i32",
            ScalarKind::I64 => "i64",
            ScalarKind::U8 => "u8",
            ScalarKind::U16 => "u16",
            ScalarKind::U32 => "u32",
            ScalarKind::U64 => "u64",
            ScalarKind::F32 => "f32",
            ScalarKind::F64 => "f64",
            ScalarKind::Ptr => "*mut u8",
            ScalarKind::Unit => "()",
        }
        .to_string()
    }
}

/// Outcome of a single test case inside the harness.
#[derive(Debug, Clone)]
pub struct HarnessTestResult {
    /// 0-based index of the case, matching the input order.
    pub index: usize,
    /// True when the call returned normally.
    pub ok: bool,
    /// The returned value, as JSON. `Null` for `void` or on error.
    pub returned: serde_json::Value,
    /// Failure detail, if any.
    pub error: Option<String>,
    /// True when the harness process died on this case.
    pub crashed: bool,
}

/// Everything one harness invocation produced.
#[derive(Debug, Clone, Default)]
pub struct HarnessReport {
    /// Per-case outcomes. Cases killed by a crash are present with
    /// `crashed: true` when isolation identified them.
    pub results: Vec<HarnessTestResult>,
    /// How many of `results` the harness actually reported, as opposed to
    /// entries synthesised after it died. Only reported cases count towards
    /// deciding whether a run finished.
    pub reported: usize,
    /// The address the module was actually mapped at, when reported.
    pub module_base: Option<u64>,
    /// Diagnostics the harness printed to stderr.
    pub stderr: String,
}

/// Field separator between arguments on the wire (ASCII unit separator).
pub const UNIT_SEPARATOR: char = '\u{1f}';

/// Locate a function inside a PE image for harness generation.
///
/// `function` is either a Ghidra `FUN_<hex>` address (which maps to an RVA),
/// or a named export.
pub fn locator_for_function(image: &crate::pe::PeImage, function: &str) -> Option<FunctionLocator> {
    // If it looks like an address, treat it as an RVA.
    if let Some(stripped) = function.strip_prefix("FUN_")
        && let Ok(hex) = u32::from_str_radix(stripped, 16)
    {
        return Some(FunctionLocator::Rva(hex - image.image_base() as u32));
    }
    // Otherwise, look it up in the export table.
    image
        .exports()
        .iter()
        .find(|e| e.name == function)
        .map(|e| FunctionLocator::ExportName(e.name.clone()))
}

/// Locate a function by its virtual address.
///
/// Takes the VA from Ghidra and returns a [`FunctionLocator::Rva`].
pub fn locator_for_va(image: &crate::pe::PeImage, va: u64) -> Option<FunctionLocator> {
    let rva = va - image.image_base();
    Some(FunctionLocator::Rva(rva as u32))
}
