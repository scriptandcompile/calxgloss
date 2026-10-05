//! Encode test cases for the harness wire format.

use anyhow::{Context, Result, bail};
use calxgloss_types::TestCase;
use serde_json::Value;

use crate::wine::types::{HarnessSpec, ScalarKind};

const MAX_ALLOC: usize = 256 * 1024 * 1024;

/// Key used in a test case's JSON to request a harness-allocated buffer.
const ALLOC_KEY: &str = "__alloc";

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
    Ok(fields.join(&crate::wine::UNIT_SEPARATOR.to_string()))
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
pub fn decode_value(payload: &str) -> Value {
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

fn parse_hex(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16)
        .with_context(|| format!("'{t}' is not a hex value"))
        .map_err(|e| e.to_string())
}
