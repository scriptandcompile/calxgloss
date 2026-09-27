//! Cross-compile and run a Windows harness under Wine to capture a ground-truth
//! baseline from an original DLL.
//!
//! # Why this is not a link-time FFI
//!
//! The obvious way to call an original function is to generate an
//! `extern "C"` block and link against the DLL. That only works for *exported*
//! symbols. The interesting functions in a real binary are internal: Ghidra
//! names them `FUN_18008ed50` and they appear in no export table. Reaching them
//! means loading the module at runtime and calling `module_base + rva`, which is
//! what this module generates.
//!
//! # Address arithmetic
//!
//! Ghidra reports addresses at the image's preferred base, so the RVA is
//! `va - image_base` (see [`crate::PeImage::rva_from_va`]). The image is
//! normally *not* loaded at its preferred base — ASLR and Wine's allocator pick
//! the address — so the runtime call target is `actual_base + rva`.
//!
//! # Loading strategy
//!
//! Two load modes are supported, because Delphi binaries such as `eqmain.dll`
//! need runtime state that a bare mapping does not provide:
//!
//! * [`LoadMode::NoResolve`] — `LoadLibraryExW` with
//!   `DONT_RESOLVE_DLL_REFERENCES`. Maps the image without running `DllMain`
//!   and without resolving imports. Sufficient for functions that touch only
//!   caller-allocated memory. Nothing from the DLL's own runtime is available.
//! * [`LoadMode::Full`] — plain load, which runs `DllMain` and resolves imports.
//!   Required for functions that read runtime-initialised state, and the only
//!   mode in which named exports reliably resolve through their import stubs.
//!
//! # Wire protocol
//!
//! The generated harness deliberately has **no dependencies**, so the
//! cross-compile stays hermetic and fast. Cases go in on stdin, results come
//! back on stdout, one line each:
//!
//! ```text
//! stdin   i64:4096<US>i32:-4<US>            (one line per case, US = 0x1f)
//! stdout  0<TAB>ok<TAB>i64:4080             (index, status, payload)
//!         1<TAB>err<TAB>expected 2 arguments, got 1
//! ```
//!
//! Floats are carried as their raw bit pattern and pointers as hex, so no
//! value is lost to text formatting.
//!
//! # Isolation
//!
//! A function that faults kills the harness process, taking every later case
//! with it. When a batch run dies without reporting all cases, the runner
//! retries case-by-case so one bad input does not discard the rest. Note that
//! this only covers *crashes*; a hang is still fatal.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use calxgloss_types::TestCase;
use serde_json::Value;
use tracing::{debug, info, instrument, warn};

use crate::Machine;
use crate::ffi::{ParsedSignature, ghidra_type_to_rust};

/// Field separator between arguments on the wire (ASCII unit separator).
pub const UNIT_SEPARATOR: char = '\u{1f}';

/// Largest buffer the generated harness will allocate for a test case.
///
/// A bound is needed because allocation size comes from test data, and a typo
/// like `"size": 4294967296` would otherwise try to exhaust memory.
const MAX_ALLOC: usize = 256 * 1024 * 1024;

/// Key used in a test case's JSON to request a harness-allocated buffer.
const ALLOC_KEY: &str = "__alloc";

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
    ///
    /// The generated harness owns the `DONT_RESOLVE_DLL_REFERENCES` constant, so
    /// the mode is communicated as a flag rather than a value.
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
    fn harness_args(&self) -> Vec<String> {
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
    fn from_rust_type(rust_type: &str, machine: Machine) -> Option<Self> {
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
    fn fn_pointer_type(&self) -> String {
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
    fn return_rust_type(&self) -> String {
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
    pub returned: Value,
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

/// Encode a test case's inputs into the wire format the harness reads.
///
/// `inputs` is keyed by parameter name, matching the names Ghidra reports.
pub fn encode_test_case(spec: &HarnessSpec, test: &TestCase) -> Result<String> {
    let Value::Object(obj) = &test.inputs else {
        bail!("Test case inputs must be a JSON object of parameter name -> value");
    };

    let mut fields = Vec::with_capacity(spec.params.len());
    for p in &spec.params {
        let value = obj.get(&p.name).with_context(|| {
            format!(
                "Test case is missing an input for parameter '{}'; present keys: {:?}",
                p.name,
                obj.keys().collect::<Vec<_>>()
            )
        })?;
        fields.push(encode_value(p.kind, &p.name, value)?);
    }
    Ok(fields.join(&UNIT_SEPARATOR.to_string()))
}

/// Encode one value for the wire, tagged with its type.
fn encode_value(kind: ScalarKind, name: &str, value: &Value) -> Result<String> {
    // Accept both decimal and `0x`-prefixed forms, since addresses are far more
    // readable in hex and the harness understands both. Output is always decimal
    // for integers, which is what the harness parses for non-float kinds.
    let as_int = |v: &Value| -> Result<i128> {
        match v {
            Value::Number(n) => n
                .as_i64()
                .map(i128::from)
                .or_else(|| n.as_u64().map(i128::from))
                .with_context(|| format!("'{name}' must be an integer, got {n}")),
            Value::String(s) => {
                let t = s.trim();
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    // Hex may exceed i64::MAX (a large unsigned address), so widen
                    // through u64 before reinterpreting as a signed value.
                    u64::from_str_radix(hex, 16)
                        .map(|u| i128::from(u as i64))
                        .with_context(|| format!("'{name}' string '{s}' is not a hex value"))
                } else {
                    t.parse::<i128>()
                        .with_context(|| format!("'{name}' string '{s}' is not an integer"))
                }
            }
            other => bail!("'{name}' must be an integer, got {other}"),
        }
    };

    let encoded = match kind {
        ScalarKind::I8 => format!(
            "{}",
            range_check(as_int(value)?, i8::MIN as i128, i8::MAX as i128, name)?
        ),
        ScalarKind::I16 => format!(
            "{}",
            range_check(as_int(value)?, i16::MIN as i128, i16::MAX as i128, name)?
        ),
        ScalarKind::I32 => format!(
            "{}",
            range_check(as_int(value)?, i32::MIN as i128, i32::MAX as i128, name)?
        ),
        ScalarKind::I64 => format!("{}", as_int(value)?),
        ScalarKind::U8 => format!("{}", range_check(as_int(value)?, 0, u8::MAX as i128, name)?),
        ScalarKind::U16 => format!(
            "{}",
            range_check(as_int(value)?, 0, u16::MAX as i128, name)?
        ),
        ScalarKind::U32 => format!(
            "{}",
            range_check(as_int(value)?, 0, u32::MAX as i128, name)?
        ),
        ScalarKind::U64 => format!("{}", as_int(value)?),
        ScalarKind::F32 | ScalarKind::F64 => {
            // Accept either a JSON number or an explicit bit pattern, so callers
            // can pin NaN payloads that JSON cannot represent.
            match value {
                Value::String(s) => s.clone(),
                other => other
                    .as_f64()
                    .map(|f| {
                        if kind == ScalarKind::F32 {
                            format!("0x{:08x}", (f as f32).to_bits())
                        } else {
                            format!("0x{:016x}", f.to_bits())
                        }
                    })
                    .with_context(|| {
                        format!("'{name}' must be a float or bit pattern, got {other}")
                    })?,
            }
        }
        ScalarKind::Ptr => match value {
            Value::Null => "null".to_string(),
            Value::Number(_) | Value::String(_) => as_int(value)?.to_string(),
            // An explicit request for a harness-allocated buffer.
            Value::Object(spec) if spec.contains_key(ALLOC_KEY) => encode_alloc(name, spec)?,
            other => bail!(
                "'{name}' must be null, an address, or an allocation request \
                 ({{\"{ALLOC_KEY}\": {{\"size\": N}}}}), got {other}"
            ),
        },
        ScalarKind::Unit => {
            bail!("'{name}' is a void value and cannot be supplied as an input")
        }
    };
    Ok(format!("{}:{encoded}", kind.tag()))
}

fn range_check(v: i128, lo: i128, hi: i128, name: &str) -> Result<i128> {
    if v < lo || v > hi {
        bail!("'{name}' value {v} is outside the range {lo}..={hi}");
    }
    Ok(v)
}

/// Encode an allocation request: `{"__alloc": {"size": N, "fill": F}}`.
///
/// `size` is required; `fill` defaults to 0 and sets every byte of the buffer.
/// A uniform fill is what makes a read observable: filling with `0xff` means any
/// `u32` the function reads back is `0xffffffff`.
fn encode_alloc(name: &str, spec: &serde_json::Map<String, Value>) -> Result<String> {
    let request = &spec[ALLOC_KEY];
    let Value::Object(request) = request else {
        bail!("'{name}': '{ALLOC_KEY}' must be an object, got {request}");
    };

    let size = request
        .get("size")
        .with_context(|| format!("'{name}': an allocation request needs a 'size' in bytes"))?;
    let size = match size {
        Value::Number(n) => n
            .as_u64()
            .with_context(|| format!("'{name}': allocation size must be a non-negative integer"))?,
        Value::String(s) => {
            let t = s.trim();
            if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).with_context(|| {
                    format!("'{name}': allocation size '{s}' is not a hex value")
                })?
            } else {
                t.parse::<u64>()
                    .with_context(|| format!("'{name}': allocation size '{s}' is not a number"))?
            }
        }
        other => bail!("'{name}': allocation size must be a number, got {other}"),
    };
    if size > MAX_ALLOC as u64 {
        bail!("'{name}': refusing to allocate {size} bytes; the limit is {MAX_ALLOC}");
    }

    let fill = match request.get("fill") {
        None | Some(Value::Null) => String::new(),
        Some(Value::Number(n)) => {
            let byte = n
                .as_u64()
                .filter(|b| *b <= u8::MAX as u64)
                .with_context(|| format!("'{name}': allocation fill must be 0..=255, got {n}"))?;
            format!(",{byte:02x}")
        }
        Some(Value::String(s)) => {
            let t = s.trim();
            let hex = t
                .strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .unwrap_or(t);
            // Two hex digits is one byte; anything else is a mistake worth naming.
            if hex.len() > 2 {
                bail!(
                    "'{name}': allocation fill '{s}' is more than one byte; fill sets every byte"
                );
            }
            format!(",{hex:0>2}")
        }
        Some(other) => bail!("'{name}': allocation fill must be a byte, got {other}"),
    };

    Ok(format!("@{size}{fill}"))
}

/// Decode one `<kind>:<value>` payload into JSON.
fn decode_value(payload: &str) -> Value {
    let Some((tag, raw)) = payload.split_once(':') else {
        // A void return carries an empty payload.
        return Value::Null;
    };
    match tag {
        "i8" | "i16" | "i32" | "i64" => raw
            .trim()
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        "u8" | "u16" | "u32" | "u64" => raw
            .trim()
            .parse::<u64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        "f32" => parse_hex(raw)
            .map(|b| Value::from(f64::from(f32::from_bits(b as u32))))
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        "f64" => parse_hex(raw)
            .map(|b| Value::from(f64::from_bits(b)))
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        // Addresses stay hex strings: they are pointers, not quantities, and a
        // 64-bit address is not representable in every JSON consumer.
        "p" => Value::String(raw.to_string()),
        _ => Value::String(payload.to_string()),
    }
}

fn parse_hex(s: &str) -> Result<u64> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16).with_context(|| format!("'{t}' is not a hex value"))
}

/// Build the generated harness's `invoke` function.
///
/// This is the only part that varies per function, so it is generated between
/// two fixed chunks of harness code.
fn generate_invoke(spec: &HarnessSpec) -> Result<String> {
    let expected = spec.params.len();
    let mut out = String::new();

    // Buffers requested by pointer arguments must outlive the call into the target
    // function, so they are held in an arena. Only emitted when a pointer is
    // actually present, otherwise it would be an unused binding.
    let has_pointer = spec.params.iter().any(|p| p.kind == ScalarKind::Ptr);

    writeln!(
        out,
        "/// Call the function under test with the arguments supplied on the wire.\n\
         fn invoke(addr: usize, fields: &[&str]) -> Result<String, String> {{\n\
         \x20   if fields.len() != {expected} {{\n\
         \x20       return Err(format!(\"expected {expected} arguments, got {{}}\", fields.len()));\n\
         \x20   }}"
    )
    .expect("writing to a String cannot fail");

    if has_pointer {
        writeln!(
            out,
            "    // Buffers requested by pointer arguments must outlive the call, so they\n\
             \x20   // are held here rather than in the argument bindings.\n\
             \x20   let mut arena: Vec<Vec<u8>> = Vec::new();"
        )
        .expect("writing to a String cannot fail");
    }

    for (i, p) in spec.params.iter().enumerate() {
        let tag = p.kind.tag();
        let parse = match p.kind {
            ScalarKind::I8 => "as_i8",
            ScalarKind::I16 => "as_i16",
            ScalarKind::I32 => "as_i32",
            ScalarKind::I64 => "as_i64",
            ScalarKind::U8 => "as_u8",
            ScalarKind::U16 => "as_u16",
            ScalarKind::U32 => "as_u32",
            ScalarKind::U64 => "as_u64",
            ScalarKind::F32 => "as_f32",
            ScalarKind::F64 => "as_f64",
            ScalarKind::Unit => "as_void",
            // A pointer may name an address or request an allocation; either way
            // it is reinterpreted as the declared pointer type, so `*mut i8` and
            // `*const u16` both work.
            ScalarKind::Ptr => {
                writeln!(
                    out,
                    "    let a{i} = ptr_arg(fields[{i}], \"{tag}\", &mut arena)? as {ty};",
                    ty = p.rust_type
                )
                .expect("writing to a String cannot fail");
                continue;
            }
        };
        writeln!(
            out,
            "    let a{i} = {parse}(field(fields[{i}], \"{tag}\")?)?;"
        )
        .expect("writing to a String cannot fail");
    }

    let arg_list = (0..expected)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join(", ");

    writeln!(
        out,
        "    type TargetFn = {};\n\
         \x20   let func: TargetFn = unsafe {{ std::mem::transmute(addr) }};",
        spec.fn_pointer_type()
    )
    .expect("writing to a String cannot fail");

    match spec.return_kind {
        ScalarKind::Unit => {
            writeln!(out, "    func({arg_list});").expect("writing to a String cannot fail");
            writeln!(out, "    Ok(String::new())").expect("writing to a String cannot fail");
        }
        kind => {
            writeln!(out, "    let r = func({arg_list});")
                .expect("writing to a String cannot fail");
            let rendered = match kind {
                // Floats go out as raw bits so NaN payloads survive.
                ScalarKind::F32 => "format!(\"f32:0x{:08x}\", r.to_bits())".to_string(),
                ScalarKind::F64 => "format!(\"f64:0x{:016x}\", r.to_bits())".to_string(),
                ScalarKind::Ptr => {
                    "if r.is_null() { \"p:null\".to_string() } else { format!(\"p:0x{:x}\", r as usize) }"
                        .to_string()
                }
                // Integers go out in decimal. `{r}` captures the binding, so no
                // positional argument is passed.
                _ => format!("format!(\"{}:{{r}}\")", kind.tag()),
            };
            writeln!(out, "    Ok({rendered})").expect("writing to a String cannot fail");
        }
    }

    writeln!(out, "}}\n").expect("writing to a String cannot fail");
    Ok(out)
}

/// Fixed harness code that precedes the generated `invoke`.
const HARNESS_PREFIX: &str = r##"// Auto-generated by calxgloss-testgen. Do not edit.
//
// Loads a Windows DLL, resolves one function inside it, and calls it once per
// input line. Test cases arrive on stdin; one result line is written to stdout
// per case. This crate intentionally has no dependencies so that cross-compiling
// it stays hermetic and fast.
use std::ffi::c_void;

type Hmodule = *mut c_void;

/// Maps the image without running DllMain and without resolving imports.
const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;

/// Largest buffer to allocate for one test case.
///
/// Mirrors the host-side limit; allocation size arrives as test data, so it needs
/// a bound here as well.
const MAX_ALLOC: usize = 256 * 1024 * 1024;

/// Field separator between arguments on stdin.
const US: char = '\u{1f}';

/// Exit status the harness uses when the function under test faulted.
const CRASH_EXIT: u32 = __CRASH_EXIT__;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Hmodule, flags: u32) -> Hmodule;
    fn GetLastError() -> u32;
    fn GetProcAddress(module: Hmodule, name: *const u8) -> *mut c_void;
    fn SetUnhandledExceptionFilter(f: Option<CrashHandler>) -> u64;
    fn TerminateProcess(handle: *mut c_void, code: u32) -> u32;
    fn GetCurrentProcess() -> *mut c_void;
}

type CrashHandler = extern "system" fn(code: u32) -> u8;

/// Terminate the process the moment a fault escapes the call under test.
///
/// Without this, Windows escalates the exception to `winedbg`, which pops up an
/// interactive crash dialog and writes a register dump to *stdout* — the same
/// stream the results travel on. Terminating here keeps a faulting test case
/// cheap, headless, and unable to corrupt the results already emitted.
extern "system" fn on_crash(_code: u32) -> u8 {
    unsafe {
        let _ = TerminateProcess(GetCurrentProcess(), CRASH_EXIT);
    }
    // Unreachable in practice; returning non-zero would resume the search.
    1
}

/// Abort with a message on stderr. Exit codes are distinct per failure mode so
/// the caller can tell a bad invocation from a bad DLL.
fn die(code: i32, msg: &str) -> ! {
    eprintln!("harness: {msg}");
    std::process::exit(code)
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16).map_err(|e| format!("'{t}' is not a hex value: {e}"))
}

/// Split a `<tag>:<value>` field, checking the tag is the one expected.
///
/// Validating the tag means a mismatch between the caller's marshalling and the
/// generated signature is reported as such, rather than surfacing as a confusing
/// parse failure on the value.
fn field<'a>(raw: &'a str, expect: &str) -> Result<&'a str, String> {
    match raw.split_once(':') {
        Some((tag, value)) if tag == expect => Ok(value),
        Some((tag, _)) => Err(format!("expected a '{expect}' field, got a '{tag}' field")),
        None => Err(format!("field '{raw}' is missing its '{expect}:' tag")),
    }
}

fn as_i8(s: &str) -> Result<i8, String> { s.trim().parse().map_err(|e| format!("i8: {e}")) }
fn as_i16(s: &str) -> Result<i16, String> { s.trim().parse().map_err(|e| format!("i16: {e}")) }
fn as_i32(s: &str) -> Result<i32, String> { s.trim().parse().map_err(|e| format!("i32: {e}")) }
fn as_i64(s: &str) -> Result<i64, String> { s.trim().parse().map_err(|e| format!("i64: {e}")) }
fn as_u8(s: &str) -> Result<u8, String> { s.trim().parse().map_err(|e| format!("u8: {e}")) }
fn as_u16(s: &str) -> Result<u16, String> { s.trim().parse().map_err(|e| format!("u16: {e}")) }
fn as_u32(s: &str) -> Result<u32, String> { s.trim().parse().map_err(|e| format!("u32: {e}")) }
fn as_u64(s: &str) -> Result<u64, String> { s.trim().parse().map_err(|e| format!("u64: {e}")) }
fn as_f32(s: &str) -> Result<f32, String> { parse_hex(s).map(|b| f32::from_bits(b as u32)) }
fn as_f64(s: &str) -> Result<f64, String> { parse_hex(s).map(f64::from_bits) }
fn as_void(_s: &str) -> Result<(), String> { Err("void value supplied as an argument".into()) }

/// Decode a pointer argument, allocating a buffer when the field asks for one.
///
/// Accepted forms:
/// - `null` — a null pointer
/// - `<addr>` — that address, in decimal or `0x`-prefixed hex
/// - `@<size>` — a freshly allocated zeroed buffer of `size` bytes
/// - `@<size>,<fill>` — a buffer of `size` bytes, every byte set to `fill`
///
/// Buffers are pushed onto `arena` so they outlive the call into the target
/// function. Each `Vec` owns its own heap allocation, so pushing more entries
/// never moves an already-handed-out pointer.
fn ptr_arg(raw: &str, expect: &str, arena: &mut Vec<Vec<u8>>) -> Result<*mut u8, String> {
    let value = field(raw, expect)?;
    let value = value.trim();
    if value.eq_ignore_ascii_case("null") {
        return Ok(std::ptr::null_mut());
    }

    if let Some(spec) = value.strip_prefix('@') {
        let (size_text, fill_text) = spec.split_once(',').unwrap_or((spec, ""));
        let size: usize = size_text
            .trim()
            .parse()
            .map_err(|e| format!("allocation size: {e}"))?;
        if size > MAX_ALLOC {
            return Err(format!(
                "refusing to allocate {size} bytes; the limit is {}",
                MAX_ALLOC
            ));
        }
        let fill: u8 = if fill_text.trim().is_empty() {
            0
        } else {
            parse_hex(fill_text).map(|b| b as u8).map_err(|e| format!("allocation fill: {e}"))?
        };
        arena.push(vec![fill; size]);
        return Ok(arena.last_mut().expect("just pushed").as_mut_ptr());
    }

    if value.starts_with("0x") || value.starts_with("0X") {
        return parse_hex(value).map(|a| a as usize as *mut u8);
    }
    value
        .parse::<i64>()
        .map(|a| a as usize as *mut u8)
        .map_err(|e| format!("pointer: {e}"))
}

/// Keep a message on a single line so the result framing stays intact.
fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

"##;

/// Fixed harness code that follows the generated `invoke`.
const HARNESS_SUFFIX: &str = r##"
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    // Installed before anything else so it also covers a fault raised by the
    // loader while mapping the DLL.
    unsafe {
        SetUnhandledExceptionFilter(Some(on_crash));
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut dll = String::new();
    let mut locator: Option<(u8, String)> = None;
    let mut flags = DONT_RESOLVE_DLL_REFERENCES;
    // When set, run only this case index. Used to survive a crash in batch mode.
    let mut isolate: Option<usize> = None;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].clone();
        let value = argv.get(i + 1).cloned().unwrap_or_default();
        // How many argv slots this flag occupies, so the loop advances correctly.
        let consumed = match arg.as_str() {
            "--dll" => { dll = value; 1 }
            "--rva" => { locator = Some((0, value)); 1 }
            "--export-name" => { locator = Some((1, value)); 1 }
            "--export-ordinal" => { locator = Some((2, value)); 1 }
            "--run-dll-main" => { flags = 0; 0 }
            "--isolate" => { isolate = value.parse().ok(); 1 }
            other => {
                eprintln!("harness: ignoring unknown argument '{other}'");
                0
            }
        };
        i += 1 + consumed;
    }

    if dll.is_empty() {
        die(2, "--dll is required");
    }
    let Some((kind, value)) = locator else {
        die(2, "one of --rva, --export-name, or --export-ordinal is required");
    };

    let base = unsafe { LoadLibraryExW(wide(&dll).as_ptr(), std::ptr::null_mut(), flags) };
    if base.is_null() {
        let e = unsafe { GetLastError() };
        die(3, &format!("LoadLibraryExW failed: GetLastError={e} (0x{e:x})"));
    }
    let base_addr = base as usize;
    eprintln!("harness: module base = 0x{base_addr:016x}");

    // The base must be the start of a mapped image, not some other allocation.
    let mz = unsafe { std::ptr::read_unaligned(base_addr as *const u16) };
    if mz != 0x5a4d {
        die(4, &format!("base 0x{base_addr:x} lacks an MZ header (read 0x{mz:04x})"));
    }

    let addr = match kind {
        0 => match parse_hex(&value) {
            Ok(rva) => base_addr + rva as usize,
            Err(e) => die(2, &e),
        },
        1 => {
            let p = unsafe { GetProcAddress(base, value.as_ptr()) };
            if p.is_null() {
                die(5, &format!("export '{value}' not found"));
            }
            p as usize
        }
        _ => {
            let Ok(ord) = value.parse::<u16>() else {
                die(2, &format!("export ordinal '{value}' is not a number"));
            };
            let p = unsafe { GetProcAddress(base, ord as usize as *const u8) };
            if p.is_null() {
                die(5, &format!("export ordinal {ord} not found"));
            }
            p as usize
        }
    };
    eprintln!("harness: function address = 0x{addr:016x}");

    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        die(6, "could not read test cases from stdin");
    }

    use std::io::Write as _;
    // Each result is emitted as it is produced rather than accumulated, because a
    // function that faults takes the process down and would otherwise discard
    // every result computed before it.
    let mut out = std::io::stdout();
    for (offset, line) in input.lines().enumerate() {
        // In isolation mode stdin carries exactly the one requested case, so the
        // first line is that case and must be labelled with the requested index.
        let index = match isolate {
            Some(requested) => requested + offset,
            None => offset,
        };
        let fields: Vec<&str> = line.split(US).filter(|f| !f.trim().is_empty()).collect();
        let result = match invoke(addr, &fields) {
            Ok(value) => format!("{index}\tok\t{}", clean(&value)),
            Err(message) => format!("{index}\terr\t{}", clean(&message)),
        };
        if writeln!(out, "{result}").is_err() || out.flush().is_err() {
            // The reader has gone away; nothing useful is left to do.
            die(7, "could not write results to stdout");
        }
    }
}
"##;

/// Exit status a generated harness uses when the function under test faulted.
///
/// Substituted into the harness source in place of `__CRASH_EXIT__`, so the
/// runner and the harness it launches cannot drift apart.
const HARNESS_CRASH_EXIT: u32 = 133;

/// Generate the complete harness source for a spec.
pub fn generate_harness(spec: &HarnessSpec) -> Result<String> {
    let mut src = String::with_capacity(8 * 1024);
    src.push_str(&HARNESS_PREFIX.replace("__CRASH_EXIT__", &HARNESS_CRASH_EXIT.to_string()));
    src.push_str(&generate_invoke(spec)?);
    src.push_str(HARNESS_SUFFIX);
    Ok(src)
}

/// Builds and runs generated harnesses under Wine.
#[derive(Debug, Clone)]
pub struct WineRunner {
    /// Directory that holds generated harness projects.
    work_dir: PathBuf,
    /// Wine executable to invoke.
    wine_bin: String,
    /// Wine prefix, used to translate host paths into Wine paths.
    prefix: PathBuf,
}

impl WineRunner {
    /// Create a runner, discovering the Wine prefix from the environment.
    pub fn new(work_dir: &Path) -> Self {
        let prefix = std::env::var("WINEPREFIX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
                PathBuf::from(home).join(".wine")
            });
        Self {
            work_dir: work_dir.to_path_buf(),
            wine_bin: std::env::var("CALXGLOSS_WINE").unwrap_or_else(|_| "wine".into()),
            prefix,
        }
    }

    /// Override the Wine executable.
    pub fn with_wine_bin(mut self, wine_bin: impl Into<String>) -> Self {
        self.wine_bin = wine_bin.into();
        self
    }

    /// Override the Wine prefix.
    pub fn with_prefix(mut self, prefix: impl Into<PathBuf>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The Wine prefix in use.
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    /// Verify Wine is installed and the expected Rust target is available.
    pub fn preflight_wine(&self) -> Result<()> {
        let status = Command::new(&self.wine_bin)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!(
                    "Could not run '{} --version'. Baseline execution needs Wine to run the \
                     cross-compiled harness. Install it, or set CALXGLOSS_WINE.",
                    self.wine_bin
                )
            })?;
        if !status.status.success() {
            bail!("'{} --version' failed", self.wine_bin);
        }
        info!(
            wine = String::from_utf8_lossy(&status.stdout).trim(),
            prefix = %self.prefix.display(),
            "Wine is available"
        );
        Ok(())
    }

    /// Translate a host path into a path Wine can open.
    ///
    /// Paths inside the prefix become `C:\...`; anything else goes through the
    /// `Z:` drive, which Wine maps to the Unix root.
    pub fn to_wine_path(&self, host_path: &Path) -> Result<String> {
        let host = host_path
            .canonicalize()
            .with_context(|| format!("Path {} does not exist", host_path.display()))?;
        let drive_c = self.prefix.join("drive_c");
        let drive_c = if drive_c.exists() {
            drive_c.canonicalize().unwrap_or(drive_c)
        } else {
            drive_c
        };

        let relative = match host.strip_prefix(&drive_c) {
            Ok(rel) => format!("C:{}", to_windows_separators(&rel.to_string_lossy())),
            // Outside the prefix: reach it through the Z: drive.
            Err(_) => format!("Z:{}", to_windows_separators(&host.to_string_lossy())),
        };
        debug!(host = %host.display(), wine = %relative, "Translated path for Wine");
        Ok(relative)
    }

    /// Write, compile, and run a harness, returning its report.
    ///
    /// A batch run that dies before reporting every case is retried one case at
    /// a time so a single faulting input is attributed rather than discarding
    /// the whole batch.
    #[instrument(skip_all, fields(function = %spec.function_label))]
    pub fn run(
        &self,
        spec: &HarnessSpec,
        dll_path: &Path,
        tests: &[TestCase],
        target: Machine,
    ) -> Result<HarnessReport> {
        let project_dir = self.write_project(spec)?;
        let exe = self.compile(&project_dir, target)?;
        let wine_dll = self.to_wine_path(dll_path)?;

        let payload: Vec<String> = tests
            .iter()
            .map(|t| encode_test_case(spec, t))
            .collect::<Result<Vec<_>>>()?;

        let mut report = self.invoke(spec, &exe, &wine_dll, &payload, None);

        // `results` is padded with synthesised crashed entries when the harness
        // dies, so its length can reach the full count even though the run fell
        // over. Compare the number the harness actually *reported* instead,
        // otherwise the placeholders for every case after the faulting one are
        // mistaken for real answers and never re-examined.
        if report.reported < tests.len() {
            // The process died partway through. Re-run each case on its own to
            // find out which one is responsible and recover the rest.
            warn!(
                function = %spec.function_label,
                reported = report.reported,
                expected = tests.len(),
                "Harness exited early; re-running each case in isolation"
            );
            let mut isolated = Vec::with_capacity(tests.len());
            for index in 0..tests.len() {
                let mut single = self.invoke(spec, &exe, &wine_dll, &payload, Some(index));
                // A case that succeeded in isolation may also have succeeded in
                // the batch; prefer the batch's reading when both agree, since
                // it came from a process that had the same runtime state.
                let batch_succeeded = report.results.iter().any(|b| b.index == index && b.ok);
                if single.reported == 1
                    && single.results[0].ok
                    && batch_succeeded
                    && let Some(batch) = report.results.iter().find(|b| b.index == index)
                {
                    single.results[0].returned = batch.returned.clone();
                }
                isolated.append(&mut single.results);
            }
            isolated.sort_by_key(|r| r.index);
            report.results = isolated;
            report.reported = report.results.iter().filter(|r| r.ok).count();
        }

        if report.results.len() < tests.len() {
            warn!(
                function = %spec.function_label,
                got = report.results.len(),
                expected = tests.len(),
                "Some test cases produced no result even in isolation"
            );
        }
        Ok(report)
    }

    /// Run the harness once, optionally restricted to a single case.
    fn invoke(
        &self,
        spec: &HarnessSpec,
        exe: &Path,
        wine_dll: &str,
        payload: &[String],
        isolate: Option<usize>,
    ) -> HarnessReport {
        let mut cmd = Command::new(&self.wine_bin);
        cmd.arg(exe)
            .arg("--dll")
            .arg(wine_dll)
            .args(spec.locator.harness_args())
            // Wine's own diagnostics drown out the harness output.
            .env("WINEDEBUG", "-all")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if spec.load_mode.runs_dll_main() {
            cmd.arg("--run-dll-main");
        }
        if let Some(index) = isolate {
            cmd.arg("--isolate").arg(index.to_string());
        }

        let stdin_payload = match isolate {
            // A single-case run must still deliver the case at the right index,
            // since the harness numbers results by input line position.
            Some(index) => payload.get(index).cloned().unwrap_or_default(),
            None => payload.join("\n"),
        };

        debug!(
            isolate = ?isolate,
            cases = payload.len(),
            "Running harness under Wine"
        );

        let mut spawn = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return HarnessReport {
                    results: failed_all(payload, isolate, format!("could not run Wine: {e}")),
                    stderr: format!("could not run Wine: {e}"),
                    ..Default::default()
                };
            }
        };

        let write_failed = match spawn.stdin.take() {
            Some(mut stdin) => stdin.write_all(stdin_payload.as_bytes()).is_err(),
            None => true,
        };
        // Dropping stdin signals EOF so the harness stops reading.

        let output = match spawn.wait_with_output() {
            Ok(out) => out,
            Err(e) => {
                return HarnessReport {
                    results: failed_all(payload, isolate, format!("harness wait failed: {e}")),
                    stderr: format!("harness wait failed: {e}"),
                    ..Default::default()
                };
            }
        };

        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

        let mut results = parse_results(&stdout);
        let reported = results.len();
        let expected = match isolate {
            Some(_) => 1,
            None => payload.len(),
        };

        if results.len() < expected {
            // A fault inside the target is caught by the harness's own crash
            // handler, which terminates with a known status. A signal death is
            // the older fallback path, kept because a fault can also happen
            // outside the handler's reach, e.g. on a loader thread.
            let crashed_in_target =
                matches!(output.status.code(), Some(code) if code as u32 == HARNESS_CRASH_EXIT);
            let signal = terminating_signal(&output.status);
            let detail = match signal {
                Some(sig) => format!(
                    "harness terminated by signal {sig} — the function under test likely \
                     faulted (stderr: {})",
                    stderr.trim()
                ),
                None if write_failed => {
                    "harness could not receive its test cases on stdin".to_string()
                }
                None if crashed_in_target => {
                    "the function under test faulted and the harness caught it".to_string()
                }
                None if !output.status.success() => format!(
                    "harness exited with status {} (stderr: {})",
                    output.status,
                    stderr.trim()
                ),
                None => "harness produced no result for this case".to_string(),
            };
            warn!(function = %spec.function_label, detail, "Harness did not report every case");
            results.extend(crashed_results(&results, payload, isolate, &detail));
        }

        HarnessReport {
            results,
            reported,
            module_base: parse_module_base(&stderr),
            stderr,
        }
    }

    /// Write the harness project to disk, reusing the directory per function.
    fn write_project(&self, spec: &HarnessSpec) -> Result<PathBuf> {
        let dir = self.work_dir.join(sanitize(&spec.function_label));
        let src = dir.join("src");
        fs_create_dir_all(&src)?;

        let manifest = "[package]\n\
             name = \"calxgloss_harness\"\n\
             version = \"0.0.0\"\n\
             edition = \"2021\"\n\
             \n\
             [[bin]]\n\
             name = \"harness\"\n\
             path = \"src/main.rs\"\n\
             \n\
             [profile.release]\n\
             panic = \"unwind\"\n\
             debug = false\n";
        write_file(&dir.join("Cargo.toml"), manifest)?;
        write_file(&src.join("main.rs"), &generate_harness(spec)?)?;

        debug!(path = %dir.display(), "Wrote harness project");
        Ok(dir)
    }

    /// Cross-compile the harness and return the path to the Windows binary.
    fn compile(&self, project_dir: &Path, machine: Machine) -> Result<PathBuf> {
        let triple = machine.target_triple();
        if triple == "unknown" {
            bail!("Unsupported target architecture; cannot build a baseline harness for it");
        }

        let output = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg(triple)
            .current_dir(project_dir)
            .output()
            .context("Failed to run 'cargo build' for the baseline harness")?;

        if !output.status.success() {
            bail!(
                "Baseline harness failed to compile for {triple}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let exe = project_dir
            .join("target")
            .join(triple)
            .join("release")
            .join("harness.exe");
        if !exe.exists() {
            bail!("Harness compiled but {} was not produced", exe.display());
        }
        Ok(exe)
    }
}

fn parse_results(stdout: &str) -> Vec<HarnessTestResult> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let index = parts.next()?.trim().parse::<usize>().ok()?;
            let status = parts.next()?.trim();
            let payload = parts.next().unwrap_or("").trim();
            Some(match status {
                "ok" => HarnessTestResult {
                    index,
                    ok: true,
                    returned: decode_value(payload),
                    error: None,
                    crashed: false,
                },
                other => HarnessTestResult {
                    index,
                    ok: false,
                    returned: Value::Null,
                    error: Some(format!("harness reported '{other}': {payload}")),
                    crashed: false,
                },
            })
        })
        .collect()
}

/// Fill in cases the harness never reported, marking them as crashed.
fn crashed_results(
    got: &[HarnessTestResult],
    payload: &[String],
    isolate: Option<usize>,
    detail: &str,
) -> Vec<HarnessTestResult> {
    let expected: Vec<usize> = match isolate {
        Some(index) => vec![index],
        None => (0..payload.len()).collect(),
    };
    expected
        .into_iter()
        .filter(|i| !got.iter().any(|r| r.index == *i))
        .map(|index| HarnessTestResult {
            index,
            ok: false,
            returned: Value::Null,
            error: Some(detail.to_string()),
            crashed: true,
        })
        .collect()
}

fn failed_all(
    payload: &[String],
    isolate: Option<usize>,
    detail: String,
) -> Vec<HarnessTestResult> {
    let indices: Vec<usize> = match isolate {
        Some(index) => vec![index],
        None => (0..payload.len()).collect(),
    };
    indices
        .into_iter()
        .map(|index| HarnessTestResult {
            index,
            ok: false,
            returned: Value::Null,
            error: Some(detail.clone()),
            crashed: true,
        })
        .collect()
}

fn parse_module_base(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|line| {
        let rest = line.split("module base = ").nth(1)?;
        parse_hex(rest.trim()).ok()
    })
}

fn to_windows_separators(path: &str) -> String {
    path.replace('/', "\\")
}

/// Make a function label safe to use as a directory name.
fn sanitize(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "harness".to_string()
    } else {
        cleaned
    }
}

fn fs_create_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create harness directory {}", path.display()))
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("Failed to write {}", path.display()))
}

/// The signal that killed a process, if it was killed by one.
///
/// Windows faults inside Wine surface this way, which is how a crash in the
/// function under test becomes visible to the runner.
fn terminating_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// Convenience for the common case of locating a Ghidra-named function by VA.
pub fn locator_for_va(image: &crate::PeImage, va: u64) -> Result<FunctionLocator> {
    let rva = image.rva_from_va(va)?;
    debug!(
        va = format_args!("0x{va:x}"),
        rva = format_args!("0x{rva:x}"),
        "Resolved VA to RVA"
    );
    Ok(FunctionLocator::Rva(rva))
}

/// Build a locator for a Ghidra function name.
///
/// Names of the form `FUN_<hex>` are resolved as internal addresses via the
/// image base; anything else is tried as an export. This mirrors how Ghidra
/// names functions, so callers can pass a Ghidra name straight through.
pub fn locator_for_function(image: &crate::PeImage, name: &str) -> Result<FunctionLocator> {
    if let Some(hex) = name.strip_prefix("FUN_") {
        let va = u64::from_str_radix(hex, 16)
            .with_context(|| format!("'{name}' is not a valid Ghidra address name", name = name))?;
        return locator_for_va(image, va);
    }
    if let Ok(rva) = image.resolve_symbol(name) {
        return Ok(FunctionLocator::Rva(rva));
    }
    bail!("'{name}' is neither a Ghidra internal address nor an export of this DLL")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_of(s: &str) -> ParsedSignature {
        crate::parse_signature(s).expect("signature should parse")
    }

    fn spec(signature: &str) -> HarnessSpec {
        HarnessSpec::new(
            "FUN_18008ed50",
            FunctionLocator::Rva(0x8ed50),
            &signature_of(signature),
            Machine::X86_64,
        )
        .expect("spec should build")
    }

    fn test_case(inputs: Value) -> TestCase {
        TestCase {
            inputs,
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
        }
    }

    #[test]
    fn generated_harness_installs_a_crash_handler_with_the_shared_exit_status() {
        let src = generate_harness(&spec("int FUN(int a)")).expect("harness should generate");
        assert!(
            !src.contains("__CRASH_EXIT__"),
            "the crash-exit placeholder must be substituted, not left in the source"
        );
        assert!(
            src.contains(&format!("const CRASH_EXIT: u32 = {HARNESS_CRASH_EXIT};")),
            "the harness must exit with the status the runner looks for"
        );
        assert!(
            src.contains("SetUnhandledExceptionFilter(Some(on_crash))"),
            "the handler must be installed, or a fault escalates to a winedbg dialog"
        );
    }

    #[test]
    fn test_classifies_scalar_types() {
        let m = Machine::X86_64;
        assert_eq!(ScalarKind::from_rust_type("i32", m), Some(ScalarKind::I32));
        assert_eq!(ScalarKind::from_rust_type("u64", m), Some(ScalarKind::U64));
        assert_eq!(ScalarKind::from_rust_type("()", m), Some(ScalarKind::Unit));
        assert_eq!(
            ScalarKind::from_rust_type("*mut u8", m),
            Some(ScalarKind::Ptr)
        );
        assert_eq!(
            ScalarKind::from_rust_type("*const i8", m),
            Some(ScalarKind::Ptr)
        );
        assert_eq!(ScalarKind::from_rust_type("f64", m), Some(ScalarKind::F64));
        assert_eq!(ScalarKind::from_rust_type("MyStruct", m), None);
    }

    #[test]
    fn test_pointer_sized_ints_follow_architecture() {
        assert_eq!(
            ScalarKind::from_rust_type("usize", Machine::X86_64),
            Some(ScalarKind::U64)
        );
        assert_eq!(
            ScalarKind::from_rust_type("usize", Machine::X86),
            Some(ScalarKind::U32)
        );
        assert_eq!(
            ScalarKind::from_rust_type("isize", Machine::X86_64),
            Some(ScalarKind::I64)
        );
        assert_eq!(
            ScalarKind::from_rust_type("isize", Machine::X86),
            Some(ScalarKind::I32)
        );
    }

    #[test]
    fn test_ghidra_signature_becomes_callable_spec() {
        let s = spec("longlong FUN_18008ed50(longlong param_1,int param_2)");
        assert_eq!(s.params.len(), 2);
        assert_eq!(s.params[0].kind, ScalarKind::I64);
        assert_eq!(s.params[1].kind, ScalarKind::I32);
        assert_eq!(s.return_kind, ScalarKind::I64);
    }

    #[test]
    fn test_void_return_is_supported() {
        let s = spec("void FUN_180081be0(undefined *param_1)");
        assert_eq!(s.return_kind, ScalarKind::Unit);
        assert_eq!(s.params[0].kind, ScalarKind::Ptr);
    }

    #[test]
    fn test_unmarshallable_type_is_rejected_with_detail() {
        let sig = signature_of("SomeStruct FUN_1(SomeStruct param_1)");
        let err =
            HarnessSpec::new("F", FunctionLocator::Rva(0), &sig, Machine::X86_64).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SomeStruct"), "unhelpful message: {msg}");
    }

    #[test]
    fn test_generated_harness_has_expected_shape() {
        let src = generate_harness(&spec(
            "longlong FUN_18008ed50(longlong param_1,int param_2)",
        ))
        .unwrap();
        assert!(
            src.contains("extern \"system\" fn(i64, i32) -> i64"),
            "{src}"
        );
        // Each argument is untagged by kind before being parsed.
        assert!(
            src.contains("let a0 = as_i64(field(fields[0], \"i64\")?)?;"),
            "{src}"
        );
        assert!(
            src.contains("let a1 = as_i32(field(fields[1], \"i32\")?)?;"),
            "{src}"
        );
        assert!(src.contains("expected 2 arguments"));
        assert!(src.contains("LoadLibraryExW"));
    }

    #[test]
    fn test_generated_harness_handles_void_return() {
        let src = generate_harness(&spec("void FUN_180081be0(undefined *param_1)")).unwrap();
        assert!(src.contains("fn(*mut u8) -> ()"), "{src}");
        // A void call must not bind an unused result.
        assert!(src.contains("func(a0);"), "{src}");
    }

    #[test]
    fn test_generated_harness_reinterprets_pointer_type() {
        let src = generate_harness(&spec("int FUN_1(char *param_1)")).unwrap();
        assert!(
            src.contains("ptr_arg(fields[0], \"p\", &mut arena)? as *mut i8"),
            "{src}"
        );
        // Allocations must be held somewhere that outlives the call.
        assert!(src.contains("let mut arena: Vec<Vec<u8>>"), "{src}");
    }

    #[test]
    fn test_generated_harness_supports_every_scalar_kind() {
        // Guards the generator against a shape that produces uncompilable code.
        // Compile-checking the output is covered by tests/baseline.rs.
        let src = generate_harness(&spec(
            "double f(i8 a,i16 b,i32 c,i64 d,u8 e,u16 f,u32 g,u64 h,float i,double j,undefined *k)",
        ))
        .unwrap_or_else(|e| panic!("every scalar should marshal: {e:#}"));
        for parser in [
            "as_i8(", "as_i16(", "as_i32(", "as_i64(", "as_u8(", "as_u16(", "as_u32(", "as_u64(",
            "as_f32(", "as_f64(", "ptr_arg(",
        ] {
            assert!(src.contains(parser), "missing {parser} in:\n{src}");
        }
    }

    #[test]
    fn test_encode_test_case_orders_and_tags_fields() {
        let s = spec("longlong FUN_18008ed50(longlong param_1,int param_2)");
        let line = encode_test_case(
            &s,
            &test_case(serde_json::json!({
                "param_1": 4096,
                "param_2": -4,
            })),
        )
        .unwrap();
        assert_eq!(line, format!("i64:4096{UNIT_SEPARATOR}i32:-4"));
    }

    #[test]
    fn test_encode_test_case_reports_missing_input() {
        let s = spec("longlong FUN_18008ed50(longlong param_1,int param_2)");
        let err =
            encode_test_case(&s, &test_case(serde_json::json!({ "param_1": 4096 }))).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("param_2"), "{msg}");
    }

    #[test]
    fn test_encode_enforces_ranges() {
        let err = encode_value(ScalarKind::U8, "p", &Value::from(256)).unwrap_err();
        assert!(format!("{err:#}").contains("outside the range"), "{err:#}");
    }

    #[test]
    fn test_encode_pointer_null_and_address() {
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &Value::Null).unwrap(),
            "p:null"
        );
        // Addresses are emitted in decimal; the harness accepts either.
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &Value::from(0x1000)).unwrap(),
            "p:4096"
        );
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &Value::String("0x1000".into())).unwrap(),
            "p:4096"
        );
    }

    #[test]
    fn test_encode_allocation_request() {
        let zeroed = serde_json::json!({ "__alloc": { "size": 1024 } });
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &zeroed).unwrap(),
            "p:@1024"
        );

        let filled = serde_json::json!({ "__alloc": { "size": "0x400", "fill": "0xff" } });
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &filled).unwrap(),
            "p:@1024,ff"
        );

        // A numeric fill is padded to two hex digits.
        let numeric = serde_json::json!({ "__alloc": { "size": 16, "fill": 7 } });
        assert_eq!(
            encode_value(ScalarKind::Ptr, "p", &numeric).unwrap(),
            "p:@16,07"
        );
    }

    #[test]
    fn test_encode_allocation_request_rejects_bad_shapes() {
        // Missing size.
        let no_size = serde_json::json!({ "__alloc": { "fill": 0 } });
        assert!(encode_value(ScalarKind::Ptr, "p", &no_size).is_err());

        // Allocation larger than the cap.
        let huge = serde_json::json!({ "__alloc": { "size": MAX_ALLOC as u64 + 1 } });
        let err = encode_value(ScalarKind::Ptr, "p", &huge).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to allocate"),
            "{err:#}"
        );

        // A fill wider than one byte cannot mean "every byte".
        let wide = serde_json::json!({ "__alloc": { "size": 16, "fill": "0xdeadbeef" } });
        let err = encode_value(ScalarKind::Ptr, "p", &wide).unwrap_err();
        assert!(format!("{err:#}").contains("more than one byte"), "{err:#}");

        // Fill out of byte range.
        let big = serde_json::json!({ "__alloc": { "size": 16, "fill": 256 } });
        assert!(encode_value(ScalarKind::Ptr, "p", &big).is_err());
    }

    #[test]
    fn test_encode_pointer_rejects_unusable_input() {
        let err = encode_value(ScalarKind::Ptr, "p", &Value::Bool(true)).unwrap_err();
        assert!(format!("{err:#}").contains("allocation request"), "{err:#}");
    }

    #[test]
    fn test_encode_float_uses_bit_pattern() {
        assert_eq!(
            encode_value(ScalarKind::F64, "f", &Value::from(1.0)).unwrap(),
            "f64:0x3ff0000000000000"
        );
        // NaN must round-trip through the explicit form.
        assert_eq!(
            encode_value(ScalarKind::F32, "f", &Value::String("0x7fc00000".into())).unwrap(),
            "f32:0x7fc00000"
        );
    }

    #[test]
    fn test_decode_roundtrip() {
        assert_eq!(decode_value("i64:-1"), Value::from(-1i64));
        assert_eq!(
            decode_value("u64:18446744073709551615"),
            Value::from(u64::MAX)
        );
        assert_eq!(decode_value("f64:0x3ff0000000000000"), Value::from(1.0f64));
        assert_eq!(decode_value("p:0x1000"), Value::from("0x1000"));
        assert_eq!(decode_value("p:null"), Value::from("null"));
        // Void returns carry no payload.
        assert_eq!(decode_value(""), Value::Null);
    }

    #[test]
    fn test_parse_results_handles_mixed_outcomes() {
        let stdout = "0\tok\ti64:4080\n1\terr\texpected 2 arguments, got 1\n2\tok\ti64:0\n";
        let results = parse_results(stdout);
        assert_eq!(results.len(), 3);
        assert!(results[0].ok);
        assert_eq!(results[0].returned, Value::from(4080i64));
        assert!(!results[1].ok);
        assert!(results[1].error.as_deref().unwrap().contains("expected 2"));
        assert!(results[2].ok);
    }

    #[test]
    fn test_parse_results_ignores_noise() {
        let results = parse_results("garbage\n0\tok\ti32:7\n\nnot a result\n");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].returned, Value::from(7i32));
    }

    #[test]
    fn test_crashed_results_only_fills_gaps() {
        let got = vec![HarnessTestResult {
            index: 0,
            ok: true,
            returned: Value::from(1),
            error: None,
            crashed: false,
        }];
        let payload = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let filled = crashed_results(&got, &payload, None, "boom");
        assert_eq!(filled.len(), 2);
        assert_eq!(filled[0].index, 1);
        assert_eq!(filled[1].index, 2);
        assert!(filled.iter().all(|r| r.crashed));
    }

    #[test]
    fn test_crashed_placeholders_are_not_counted_as_reported() {
        // The shape that hid the real fault: a batch that reported one case and
        // then died. Padding the gap brings `results` to full length, so the
        // only way to notice the run fell over is to count reported cases.
        let reported = vec![HarnessTestResult {
            index: 0,
            ok: true,
            returned: Value::from(7),
            error: None,
            crashed: false,
        }];
        let payload = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let padded = reported
            .iter()
            .cloned()
            .chain(crashed_results(&reported, &payload, None, "boom"))
            .collect::<Vec<_>>();

        assert_eq!(padded.len(), payload.len());
        assert_eq!(
            padded.iter().filter(|r| !r.crashed).count(),
            1,
            "only the case the harness actually answered counts as reported"
        );
    }

    #[test]
    fn test_parse_module_base() {
        let stderr = "harness: module base = 0x00007ffab1234000\nharness: function address = 0x0\n";
        assert_eq!(parse_module_base(stderr), Some(0x0000_7ffa_b123_4000));
        assert_eq!(parse_module_base("nothing here"), None);
    }

    #[test]
    fn test_sanitize_makes_directory_names() {
        assert_eq!(sanitize("FUN_18008ed50"), "FUN_18008ed50");
        assert_eq!(sanitize("weird/name with spaces"), "weird_name_with_spaces");
        assert_eq!(sanitize(""), "harness");
    }

    #[test]
    fn test_locator_args_are_explicit_about_rva() {
        assert_eq!(
            FunctionLocator::Rva(0x8ed50).harness_args(),
            vec!["--rva".to_string(), "0x8ed50".to_string()]
        );
        assert_eq!(
            FunctionLocator::ExportOrdinal(2).harness_args(),
            vec!["--export-ordinal".to_string(), "2".to_string()]
        );
    }
}
