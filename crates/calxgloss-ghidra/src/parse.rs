//! Parsers for GhidraMCP's response bodies.
//!
//! Most endpoints answer `text/plain`, and the formats are positional rather
//! than structured, so parsing is done by splitting on the separators the
//! server actually emits. The 6.x bridge answers a handful of endpoints
//! (`get_current_address`, `get_current_function`, `list_imports`,
//! `list_open_programs`) in JSON; those parsers accept JSON first and fall
//! back to the plain-text shape, so one client build works against either.
//! Anything unparseable is skipped rather than guessed at: a half-understood
//! address is worse than a missing record, because it would silently produce a
//! wrong call target.

use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionBody,
    FunctionSummary, OpenProgram, Segment, StringLiteral, StructFieldLayout, StructLayout, Symbol,
    Xref,
};
use serde_json::Value;

/// Split a response into records, discarding blank lines.
///
/// The server does not always terminate the last line, and some responses
/// arrive with leading blank lines, so records are trimmed and empties dropped
/// rather than indexed positionally.
pub fn records(body: &str) -> Vec<&str> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse a bare hex address, with or without a `0x` prefix.
///
/// Ghidra writes addresses without a prefix (`18008ed50`), so the bare form has
/// to be accepted, and any `0x` prefix is tolerated.
pub fn parse_address(text: &str) -> Option<u64> {
    let t = text.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

/// Read a top-level string field out of a JSON object body.
///
/// Used by the JSON-shaped endpoints, whose fields the parsers pick out one at
/// a time rather than through a full serde model.
pub fn json_string(body: &str, field: &str) -> Option<String> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get(field)?
        .as_str()
        .map(str::to_string)
}

/// Parse a `get_current_address` response.
///
/// The 6.x bridge answers JSON (`{"address":"1800e2110",...}`); older builds
/// answered a bare hex line, which the plain address parser still accepts.
pub fn parse_current_address(body: &str) -> Option<u64> {
    json_string(body, "address")
        .and_then(|a| parse_address(&a))
        .or_else(|| parse_address(body))
}

/// Parse a `get_current_function` response.
///
/// The 6.x bridge answers JSON (`{"function_name":..., "address":...}`), which
/// carries no body range, so the function is reported as spanning no bytes —
/// the same shape the text parser gives a function with no `Body:` line.
pub fn parse_current_function(body: &str) -> Option<FunctionBody> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let name = value.get("function_name")?.as_str()?;
        let entry = parse_address(value.get("address")?.as_str()?)?;
        return Some(FunctionBody {
            name: name.to_string(),
            entry,
            end: entry,
        });
    }
    parse_function_body(body)
}

/// Parse a function listing entry: `name at 18008ed50` or `name @ 18008ed50`.
///
/// Ghidra's own names contain no ` at ` or ` @ `, so the last such separator
/// separates the name from the address.
pub fn parse_function_summary(line: &str) -> Option<FunctionSummary> {
    for sep in [" @ ", " at "] {
        if let Some((name, addr)) = line.rsplit_once(sep) {
            let name = name.trim();
            let address = parse_address(addr)?;
            if name.is_empty() {
                return None;
            }
            return Some(FunctionSummary {
                name: name.to_string(),
                address,
            });
        }
    }
    None
}

/// Parse a function listing, skipping records that do not fit.
pub fn parse_function_listing(body: &str) -> Vec<FunctionSummary> {
    records(body)
        .into_iter()
        .filter_map(parse_function_summary)
        .collect()
}

/// Parse a `get_function_by_address` response.
///
/// The server writes up to four labelled lines:
/// ```text
/// Function: FUN_18008ed50 at 18008ed50
/// Signature: undefined FUN_18008ed50(void)
/// Entry: 18008ed50
/// Body: 18008ed50 - 18008ed5b
/// ```
/// The `Signature:` line is deliberately dropped: it reports
/// `undefined name(void)` for any function whose parameters Ghidra has not
/// been told about, which is nearly all of them.
///
/// A function with no body yet — an entry point, or a stub Ghidra has not
/// followed — omits the `Entry:` and `Body:` lines entirely, leaving only the
/// `Function:` line. That is a real shape, so the address is read from there and
/// the body is reported as empty rather than treated as unparseable.
pub fn parse_function_body(text: &str) -> Option<FunctionBody> {
    let mut name = None;
    let mut entry = None;
    let mut end = None;

    for line in records(text) {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        match label.trim() {
            "Function" => {
                // The value is `name at ADDR`, the same shape a listing record
                // has, so it is read with the listing parser.
                match parse_function_summary(value) {
                    Some(summary) => {
                        name = Some(summary.name);
                        entry.get_or_insert(summary.address);
                    }
                    // No address on the line; the name alone is still usable.
                    None => name = value.split_whitespace().next().map(str::to_string),
                }
            }
            "Entry" => entry = parse_address(value),
            "Body" => {
                let Some((lo, hi)) = value.split_once('-') else {
                    continue;
                };
                entry = parse_address(lo).or(entry);
                end = parse_address(hi);
            }
            _ => {}
        }
    }

    let entry = entry?;
    Some(FunctionBody {
        name: name?,
        entry,
        // A missing `Body:` line means the function spans no bytes.
        end: end.unwrap_or(entry),
    })
}

/// Parse a cross-reference record.
///
/// `/get_xrefs_to` and `/get_function_xrefs` write
/// `From 18000a3be in FUN_18000a0d0 [UNCONDITIONAL_CALL]`; `/get_xrefs_from`
/// writes `To 18008ed50 to function FUN_18008ed50 [UNCONDITIONAL_CALL]`. Both
/// are accepted, and the direction word is ignored because the caller already
/// knows which endpoint it asked.
pub fn parse_xref(line: &str) -> Option<Xref> {
    let rest = line
        .strip_prefix("From ")
        .or_else(|| line.strip_prefix("To "))?;

    // Peel off the trailing `[KIND]` first, so a kind containing spaces cannot
    // be mistaken for part of the function name.
    let (rest, kind) = match rest.rfind('[') {
        Some(open) if rest.ends_with(']') => (
            rest[..open].trim_end(),
            Some(rest[open + 1..rest.len() - 1].trim().to_string()),
        ),
        _ => (rest, None),
    };

    let (addr_part, function) = match rest.find(" to function ").or_else(|| rest.find(" in ")) {
        Some(idx) => (
            rest[..idx].trim(),
            Some(
                rest[idx..]
                    .trim_start_matches(" to function ")
                    .trim_start_matches(" in ")
                    .trim(),
            ),
        ),
        None => (rest, None),
    };

    let address = parse_address(addr_part)?;
    Some(Xref {
        address,
        function: function.filter(|f| !f.is_empty()).map(str::to_string),
        kind: kind.filter(|k| !k.is_empty()),
    })
}

/// Parse a cross-reference listing.
pub fn parse_xrefs(body: &str) -> Vec<Xref> {
    records(body).into_iter().filter_map(parse_xref).collect()
}

/// Parse a symbol record: `dll_main -> 18000c690`.
///
/// An address of `EXTERNAL:00000001` marks an import, whose "address" is a slot
/// the loader will fill rather than a location in the image.
pub fn parse_symbol(line: &str) -> Option<Symbol> {
    let (name, addr) = line.rsplit_once("->")?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let addr = addr.trim();

    // Imports are addressed as `EXTERNAL:<n>` rather than in hex, so the marker
    // is read before falling back to a hex parse.
    let (address, imported) = match addr.strip_prefix("EXTERNAL:") {
        Some(slot) => (parse_address(slot).unwrap_or_default(), true),
        None => (parse_address(addr)?, false),
    };

    Some(Symbol {
        name: name.to_string(),
        address,
        imported,
    })
}

/// Parse an export or import listing.
pub fn parse_symbols(body: &str, imported: bool) -> Vec<Symbol> {
    records(body)
        .into_iter()
        .filter_map(parse_symbol)
        .map(|mut s| {
            s.imported = s.imported || imported;
            s
        })
        .collect()
}

/// Parse a JSON symbol array, as `list_imports` answers on the 6.x bridge:
/// `[{"name":"...","address":"EXTERNAL:00000001"}]`.
///
/// Returns `None` when the body is not a JSON array, so the caller can fall
/// back to the plain-text listing parser.
pub fn parse_symbols_json(body: &str, imported: bool) -> Option<Vec<Symbol>> {
    let items = serde_json::from_str::<Value>(body).ok()?;
    let items = items.as_array()?;
    Some(
        items
            .iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?;
                if name.is_empty() {
                    return None;
                }
                // Same external-slot convention as the text form.
                let addr = item.get("address").and_then(Value::as_str).unwrap_or("");
                let (address, external) = match addr.strip_prefix("EXTERNAL:") {
                    Some(slot) => (parse_address(slot).unwrap_or_default(), true),
                    None => (parse_address(addr)?, false),
                };
                Some(Symbol {
                    name: name.to_string(),
                    address,
                    imported: imported || external,
                })
            })
            .collect(),
    )
}

/// Parse a `list_open_programs` response:
/// `{"programs":[{"name":..., "path":..., "is_current":..., ...}], ...}`.
pub fn parse_open_programs(body: &str) -> Vec<OpenProgram> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(items) = value.get("programs").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?;
            let path = item.get("path").and_then(Value::as_str).unwrap_or("");
            Some(OpenProgram {
                name: name.to_string(),
                path: path.to_string(),
                is_current: item
                    .get("is_current")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                function_count: item.get("function_count").and_then(Value::as_u64),
            })
        })
        .collect()
}

/// Parse a segment record: `.text: 180001000 - 1801261ff`.
pub fn parse_segment(line: &str) -> Option<Segment> {
    let (name, range) = line.split_once(':')?;
    let name = name.trim();
    let (start, end) = range.split_once('-')?;
    Some(Segment {
        name: name.to_string(),
        start: parse_address(start)?,
        end: parse_address(end)?,
    })
}

/// Parse a segment listing.
pub fn parse_segments(body: &str) -> Vec<Segment> {
    records(body)
        .into_iter()
        .filter_map(parse_segment)
        .collect()
}

/// Parse a string literal record: `180127cd8: "Everquest"`.
pub fn parse_string_literal(line: &str) -> Option<StringLiteral> {
    let (addr, quoted) = line.split_once(':')?;
    let address = parse_address(addr)?;
    let value = quoted.trim();
    // The server always quotes and escapes; a record without quotes is a
    // different kind of datum and is skipped rather than guessed at.
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(StringLiteral {
        address,
        value: unescape(value),
    })
}

/// Undo the escaping the server applies to string contents.
///
/// A string literal that decoded incorrectly would put the wrong text into test
/// inputs, so backslash escapes are handled rather than passed through raw.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            // A lone backslash or an unknown escape is kept verbatim, so the
            // text is never silently shortened.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Parse a decompiled function.
///
/// The body looks like:
/// ```text
///
/// longlong FUN_18008ed50(longlong param_1,int param_2)
///
/// {
///   return param_1 + ((longlong)param_2 + 4) * 8;
/// }
/// ```
/// The signature is the first non-blank line and the pseudo-C follows. The two
/// are separated at the `{` that opens the body, which is usually on its own
/// line but can share the signature's.
pub fn parse_decompiled(text: &str) -> Option<DecompiledFunction> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("/*") && !l.starts_with("//"))?;
    if !line.contains('(') {
        return None;
    }

    // A body brace on the signature line is not part of the declarator, and
    // leaving it there would make the signature unparseable as a C declaration.
    let signature = match line.find('{') {
        Some(idx) => line[..idx].trim_end(),
        None => line,
    };
    if !signature.contains('(') {
        return None;
    }

    // Take the name as the last identifier before the parameter list, so a
    // return type containing parentheses cannot be mistaken for the name.
    let name = signature
        .split('(')
        .next()?
        .split_whitespace()
        .next_back()?
        .to_string();

    Some(DecompiledFunction {
        name,
        signature: signature.to_string(),
        body: text.trim().to_string(),
    })
}

/// Names of functions called by a decompiled body.
///
/// The decompiler already names every direct call target as `NAME(`, so the
/// call graph's callee half can be read off the body without a request per call
/// site. A call through a function pointer is missed, because the callee is only
/// a value there and not a name in the text.
pub fn callees_from_decompiled(text: &str) -> Vec<String> {
    // Only lines between the outermost braces are scanned. The signature sits
    // outside them and ends in `(...)` too, so scanning the whole text would
    // make every function its own callee.
    let Some(open) = text.find('{') else {
        return Vec::new();
    };
    let Some(close) = text.rfind('}') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }

    let mut found: Vec<String> = Vec::new();
    for line in text[open + 1..close].lines() {
        for name in call_targets(line) {
            if !found.iter().any(|n| n == name) {
                found.push(name.to_string());
            }
        }
    }
    found
}

/// Ghidra's prefixes for a function it has no real name for.
fn is_ghidra_name(ident: &str) -> bool {
    ident.starts_with("FUN_") || ident.starts_with("LAB_") || ident.starts_with("SUB_")
}

/// Ghidra-named identifiers on `line` that are applied to an argument list.
///
/// The test is that the identifier is *immediately* followed by `(`, not that a
/// `(` appears somewhere on the line: a cast such as `(int **)FUN_1800861f0(x)`
/// puts a parenthesis earlier, and the call is the one that matters.
fn call_targets(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !(c.is_ascii_alphanumeric() || c == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let mut after = i;
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if after < bytes.len() && bytes[after] == b'(' {
            let ident = &line[start..i];
            if is_ghidra_name(ident) {
                out.push(ident);
            }
        }
    }
    out
}

/// Parse a `/list_data_types` page: `name | category | N bytes | path`.
///
/// The split runs from the right so a name that itself contains ` | ` cannot
/// swallow the other fields. A `variable` size becomes `None`, and the
/// "No data types found" sentinel yields no records rather than an error.
pub fn parse_data_types(body: &str) -> Vec<DataTypeEntry> {
    records(body)
        .into_iter()
        .filter_map(|line| {
            let mut parts = line.rsplitn(4, " | ");
            let path = parts.next()?;
            let size = parts.next()?;
            let category = parts.next()?;
            let name = parts.next()?;
            if name.is_empty() {
                return None;
            }
            Some(DataTypeEntry {
                name: name.to_string(),
                category: category.to_string(),
                size: size.strip_suffix(" bytes").and_then(|s| s.parse().ok()),
                path: path.to_string(),
            })
        })
        .collect()
}

/// Parse a `/list_data_items` page: `LABEL @ addr [TYPE] (N bytes)`.
///
/// The address separator is taken from the right, matching the function
/// listing convention, and the size group from the right of the remainder so
/// a type name containing spaces cannot shift the fields.
pub fn parse_data_items(body: &str) -> Vec<DataItem> {
    records(body)
        .into_iter()
        .filter_map(|line| {
            let (label, rest) = line.rsplit_once(" @ ")?;
            let mut rest = rest.splitn(2, ' ');
            let address = parse_address(rest.next()?)?;
            let tail = rest.next()?.trim();
            let (type_group, size_group) = tail.rsplit_once(" (")?;
            let type_name = type_group.strip_prefix('[')?.strip_suffix(']')?;
            let size = size_group
                .strip_suffix(')')?
                .trim_end_matches(" bytes")
                .trim_end_matches(" byte")
                .parse()
                .ok()?;
            Some(DataItem {
                label: label.to_string(),
                address,
                type_name: type_name.to_string(),
                length: size,
            })
        })
        .collect()
}

/// Parse a `get_struct_layout` body: a header block followed by
/// `offset | size | type | name` field lines.
///
/// Returns `None` for the server's sentinel bodies (`Structure not found: …`,
/// `Data type is not a structure: …`) so the caller can turn them into a
/// proper error; the column header and separator lines are skipped because
/// they do not fit the field shape.
pub fn parse_struct_layout(body: &str) -> Option<StructLayout> {
    let mut lines = records(body).into_iter();
    let name = lines.next()?.strip_prefix("Structure: ")?.to_string();
    let size: u64 = lines
        .next()?
        .strip_prefix("Size: ")?
        .strip_suffix(" bytes")?
        .parse()
        .ok()?;
    let alignment: u64 = lines.next()?.strip_prefix("Alignment: ")?.parse().ok()?;
    let fields = lines
        .filter_map(|line| {
            let mut parts = line.rsplitn(4, " | ");
            let field_name = parts.next()?;
            let type_name = parts.next()?;
            let size: u64 = parts.next()?.trim().parse().ok()?;
            let offset: u64 = parts.next()?.trim().parse().ok()?;
            Some(StructFieldLayout {
                offset,
                size,
                type_name: type_name.trim().to_string(),
                field_name: field_name.to_string(),
            })
        })
        .collect();
    Some(StructLayout {
        name,
        size,
        alignment,
        fields,
    })
}

/// Parse a `get_enum_values` body: a header block followed by
/// `name | value (0x…)` member lines.
///
/// Returns `None` for the server's sentinel bodies (`Enumeration not found: …`,
/// `Data type is not an enumeration: …`) so the caller can turn them into a
/// proper error.
pub fn parse_enum_values(body: &str) -> Option<EnumDefinition> {
    let mut lines = records(body).into_iter();
    let name = lines.next()?.strip_prefix("Enumeration: ")?.to_string();
    let size: u64 = lines
        .next()?
        .strip_prefix("Size: ")?
        .strip_suffix(" bytes")?
        .parse()
        .ok()?;
    let members = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(" | ")?;
            let value: i64 = value.split(" (").next()?.parse().ok()?;
            Some(EnumMember {
                name: name.to_string(),
                value,
            })
        })
        .collect();
    Some(EnumDefinition {
        name,
        size,
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fixtures below are verbatim bodies captured from GhidraMCP 1.4 with
    // `eqmain.dll` open. They are the contract: if the server's format changes,
    // these are what must change with it.

    #[test]
    fn test_parses_a_function_listing() {
        // `GET /list_functions`
        let body =
            "FUN_180001090 at 180001090\nFUN_1800010c0 at 1800010c0\nFUN_1800010f0 at 1800010f0\n";
        let functions = parse_function_listing(body);
        assert_eq!(functions.len(), 3);
        assert_eq!(
            functions[0],
            FunctionSummary {
                name: "FUN_180001090".into(),
                address: 0x180001090,
            }
        );
    }

    #[test]
    fn test_parses_a_search_result() {
        // `GET /search_functions?name_pattern=...` uses `@` where the listing uses `at`.
        let body = "FUN_18008ed50 @ 18008ed50\n";
        let found = parse_function_listing(body);
        assert_eq!(
            found,
            vec![FunctionSummary {
                name: "FUN_18008ed50".into(),
                address: 0x18008ed50,
            }]
        );
    }

    #[test]
    fn test_a_name_containing_at_is_still_split_correctly() {
        // The separator is taken from the right, so a name that itself contains
        // ` at ` cannot swallow the address.
        let found =
            parse_function_summary("widget at 18008ed50 at 180010000").expect("should parse");
        assert_eq!(found.name, "widget at 18008ed50");
        assert_eq!(found.address, 0x180010000);
    }

    #[test]
    fn test_parses_function_metadata() {
        // `GET /get_function_by_address?address=0x18008ed50`
        let body = "Function: FUN_18008ed50 at 18008ed50\nSignature: undefined FUN_18008ed50(void)\nEntry: 18008ed50\nBody: 18008ed50 - 18008ed5b\n";
        let f = parse_function_body(body).expect("should parse");
        assert_eq!(f.name, "FUN_18008ed50");
        assert_eq!(f.entry, 0x18008ed50);
        assert_eq!(f.end, 0x18008ed5b);
        // 0x0b bytes, matching the four instructions Ghidra reports.
        assert_eq!(f.len(), 0x0b);
    }

    #[test]
    fn test_parses_a_function_with_no_body() {
        // `GET /get_current_function` when the cursor sits on `entry` returns
        // only the `Function:` line. That is a real shape, not a broken
        // response, and its address is still readable.
        let body = "Function: entry at 1800e2110\nSignature: undefined entry(void)\n";
        let f = parse_function_body(body).expect("should parse");
        assert_eq!(f.name, "entry");
        assert_eq!(f.entry, 0x1800e2110);
        // A missing `Body:` line means the function spans no bytes.
        assert!(f.is_empty());
    }

    #[test]
    fn test_an_explicit_entry_line_overrides_the_address_on_the_function_line() {
        let body = "Function: FUN_x at 18008ed50\nEntry: 18008ed50\nBody: 18008ed50 - 18008ed5b\n";
        let f = parse_function_body(body).expect("should parse");
        assert_eq!(f.entry, 0x18008ed50);
        assert_eq!(f.end, 0x18008ed5b);
    }

    #[test]
    fn test_rejects_a_response_with_no_name() {
        // With no name there is nothing to report, so the record is skipped
        // rather than returned with a placeholder name.
        assert!(parse_function_body("Entry: 18008ed50\nBody: 18008ed50 - 18008ed5b\n").is_none());
    }

    #[test]
    fn test_parses_a_cross_reference() {
        // `GET /get_xrefs_to?address=0x18008ed50`
        let body = "From 18000a3be in FUN_18000a0d0 [UNCONDITIONAL_CALL]";
        let xrefs = parse_xrefs(body);
        assert_eq!(
            xrefs,
            vec![Xref {
                address: 0x18000a3be,
                function: Some("FUN_18000a0d0".into()),
                kind: Some("UNCONDITIONAL_CALL".into()),
            }]
        );
    }

    #[test]
    fn test_parses_an_outgoing_cross_reference() {
        // `GET /get_xrefs_from?address=0x18000a3be` uses a different wording for
        // the same shape, and does not terminate its last line.
        let body = "To 18008ed50 to function FUN_18008ed50 [UNCONDITIONAL_CALL]";
        let xrefs = parse_xrefs(body);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].address, 0x18008ed50);
        assert_eq!(xrefs[0].function.as_deref(), Some("FUN_18008ed50"));
    }

    #[test]
    fn test_cross_reference_without_a_kind_still_parses() {
        let xrefs = parse_xrefs("From 180127cd8 in FUN_180001090");
        assert_eq!(xrefs[0].address, 0x180127cd8);
        assert_eq!(xrefs[0].function.as_deref(), Some("FUN_180001090"));
        assert_eq!(xrefs[0].kind, None);
    }

    #[test]
    fn test_parses_an_export() {
        // `GET /list_exports`
        let body = "Ordinal_2 -> 18000c690\ndll_main -> 18000c690\nentry -> 1800e2110\n";
        let exports = parse_symbols(body, false);
        assert_eq!(exports.len(), 3);
        assert_eq!(exports[1].name, "dll_main");
        assert_eq!(exports[1].address, 0x18000c690);
        assert!(!exports[1].imported);
    }

    #[test]
    fn test_parses_an_import() {
        // `GET /list_imports` — an import's address is an external slot, not hex
        // in the image, and its name is an ordinal when imported that way.
        let body = "Ordinal_7 -> EXTERNAL:00000001\nOrdinal_6 -> EXTERNAL:00000002\n";
        let imports = parse_symbols(body, true);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name, "Ordinal_7");
        assert_eq!(imports[0].address, 1);
        assert!(imports[0].imported);
    }

    #[test]
    fn test_parses_segments() {
        // `GET /list_segments`
        let body = "Headers: 180000000 - 1800003ff\n.text: 180001000 - 1801261ff\n.rdata: 180127000 - 180172fff\n";
        let segments = parse_segments(body);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].name, "Headers");
        assert_eq!(segments[0].start, 0x180000000);
        // The first segment's start is the image base.
        assert_eq!(segments[0].start.min(segments[1].start), 0x180000000);
    }

    #[test]
    fn test_parses_a_string_literal() {
        // `GET /list_strings`
        let body = "180127cd8: \"Everquest\"\n180128cd0: \"LoggingOn\"\n";
        let strings: Vec<StringLiteral> = records(body)
            .into_iter()
            .filter_map(parse_string_literal)
            .collect();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].address, 0x180127cd8);
        assert_eq!(strings[0].value, "Everquest");
    }

    #[test]
    fn test_unescapes_string_contents() {
        let lit = parse_string_literal(r#"180127cd8: "a\"b\\c\nd""#).expect("should parse");
        assert_eq!(lit.value, "a\"b\\c\nd");
    }

    #[test]
    fn test_parses_decompiled_output() {
        // `GET /decompile_function?address=0x18008ed50`
        let body = "\nlonglong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return param_1 + ((longlong)param_2 + 4) * 8;\n}\n";
        let f = parse_decompiled(body).expect("should parse");
        assert_eq!(f.name, "FUN_18008ed50");
        // The signature is the one thing `get_function_by_address` gets wrong,
        // so recovering it here is the reason this parser exists.
        assert_eq!(
            f.signature,
            "longlong FUN_18008ed50(longlong param_1,int param_2)"
        );
        assert!(f.body.contains("return param_1"));
    }

    #[test]
    fn test_a_body_brace_on_the_signature_line_is_not_part_of_the_signature() {
        // Ghidra usually puts the brace on its own line, but a short function
        // can come back on one line. The declarator has to end at the brace or
        // it is not a signature at all.
        let f = parse_decompiled("int DrawSprite(int x, int y) { return x + y; }")
            .expect("should parse");
        assert_eq!(f.signature, "int DrawSprite(int x, int y)");
        assert_eq!(f.name, "DrawSprite");
        assert_eq!(f.parameter_names(), vec!["x", "y"]);
    }

    #[test]
    fn test_decompiled_parameter_names_match_the_signature() {
        // Test generation keys inputs by parameter name, so these have to be the
        // names the signature actually uses.
        let f = parse_decompiled("int FUN_x(int param_1,uint param_2,char *param_3)").unwrap();
        assert_eq!(f.parameter_names(), vec!["param_1", "param_2", "param_3"]);
    }

    #[test]
    fn test_decompiled_with_no_parameters() {
        let f = parse_decompiled("void FUN_x(void)\n{\n  return;\n}").unwrap();
        assert!(f.parameter_names().is_empty());
    }

    #[test]
    fn test_finds_callees_in_decompiled_output() {
        // Excerpt from `FUN_18000a0d0`, which is what the pipeline needs a call
        // graph for. `FUN_18008ed50` is genuinely called by this function.
        let body = "void FUN_18000a0d0(void)\n{\n  ppiVar4 = (int **)FUN_1800861f0(local_58);\n  uVar2 = FUN_180069f80(DAT_180381878,1);\n  FUN_180085460();\n}\n";
        let callees = callees_from_decompiled(body);
        assert!(callees.contains(&"FUN_1800861f0".to_string()));
        assert!(callees.contains(&"FUN_180069f80".to_string()));
        assert!(callees.contains(&"FUN_180085460".to_string()));
    }

    #[test]
    fn test_does_not_mistake_a_definition_for_a_call() {
        // The decompiler's own signature line ends in `(...)` too, and counting
        // it would make every function its own callee.
        let body = "int FUN_18008ed50(int param_1)\n{\n  return param_1;\n}\n";
        assert!(callees_from_decompiled(body).is_empty());
    }

    #[test]
    fn test_deduplicates_repeated_callees() {
        let body = "void f(void)\n{\n  FUN_1();\n  FUN_1();\n  FUN_2();\n}\n";
        assert_eq!(callees_from_decompiled(body), vec!["FUN_1", "FUN_2"]);
    }

    #[test]
    fn test_parses_addresses_with_and_without_a_prefix() {
        assert_eq!(parse_address("18008ed50"), Some(0x18008ed50));
        assert_eq!(parse_address("0x18008ed50"), Some(0x18008ed50));
        assert_eq!(parse_address(" 18008ed50 "), Some(0x18008ed50));
        assert_eq!(parse_address(""), None);
        assert_eq!(parse_address("not-hex"), None);
    }

    #[test]
    fn test_skips_unparseable_records_rather_than_guessing() {
        // A wrong address is worse than a missing record: it would become a
        // wrong call target downstream.
        let body = "FUN_180001090 at 180001090\ngarbage\nFUN_x at zzz\n";
        let functions = parse_function_listing(body);
        assert_eq!(functions.len(), 1);
    }

    // The fixtures below are verbatim bodies captured from the GhidraMCP 6.x
    // bridge with `eqmain.dll` open.

    #[test]
    fn test_parses_current_address_from_json_and_text() {
        // `GET /get_current_address` on the 6.x bridge.
        let body = "{\"address\":\"1800e2110\",\"program\":\"/eqmain.dll\"}";
        assert_eq!(parse_current_address(body), Some(0x1800e2110));
        // Older builds answered a bare hex line.
        assert_eq!(parse_current_address("1800e2110"), Some(0x1800e2110));
        assert_eq!(parse_current_address("{\"address\":\"not-hex\"}"), None);
    }

    #[test]
    fn test_parses_current_function_from_json_and_text() {
        // `GET /get_current_function` on the 6.x bridge.
        let body =
            "{\"function_name\":\"entry\",\"address\":\"1800e2110\",\"program\":\"/eqmain.dll\",\"signature\":\"undefined entry(void)\"}";
        let f = parse_current_function(body).expect("should parse");
        assert_eq!(f.name, "entry");
        assert_eq!(f.entry, 0x1800e2110);
        // The JSON shape carries no body range, so the function spans no bytes.
        assert!(f.is_empty());
        // Older builds answered the labelled text shape.
        let text = "Function: entry at 1800e2110\nSignature: undefined entry(void)\n";
        let f = parse_current_function(text).expect("should parse");
        assert_eq!(f.name, "entry");
        assert_eq!(f.entry, 0x1800e2110);
    }

    #[test]
    fn test_parses_imports_from_json_array() {
        // `GET /list_imports` on the 6.x bridge answers JSON.
        let body =
            "[{\"name\":\"Ordinal_7\",\"address\":\"EXTERNAL:00000001\"},{\"name\":\"dll_main\",\"address\":\"18000c690\"}]";
        let imports = parse_symbols_json(body, true).expect("should parse as JSON");
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name, "Ordinal_7");
        assert_eq!(imports[0].address, 1);
        assert!(imports[0].imported);
        // A hex address is in the image, but the caller asked for imports, so
        // the flag still holds.
        assert_eq!(imports[1].address, 0x18000c690);
        assert!(imports[1].imported);
        // A text body is not JSON, so the caller falls back to the text parser.
        assert!(parse_symbols_json("Ordinal_7 -> EXTERNAL:00000001", true).is_none());
    }

    #[test]
    fn test_parses_open_programs() {
        // `GET /list_open_programs` on the 6.x bridge.
        let body = "{\"programs\":[{\"name\":\"eqmain.dll\",\"path\":\"/eqmain.dll\",\"is_current\":true,\"function_count\":4587}],\"count\":1,\"current_program\":\"eqmain.dll\"}";
        let programs = parse_open_programs(body);
        assert_eq!(programs.len(), 1);
        assert_eq!(programs[0].name, "eqmain.dll");
        assert_eq!(programs[0].path, "/eqmain.dll");
        assert!(programs[0].is_current);
        assert_eq!(programs[0].function_count, Some(4587));
        // A malformed body yields no records rather than a failure.
        assert!(parse_open_programs("not json").is_empty());
    }

    #[test]
    fn test_parses_a_data_types_page() {
        // `GET /list_data_types?offset=0&limit=4` on the 6.x bridge, eqmain.dll.
        let body = "<lambda_01a7098693036236037e7cdb9bca3d73> | demangler | 1 bytes | /Demangler/<lambda_01a7098693036236037e7cdb9bca3d73>\n<lambda_01a7098693036236037e7cdb9bca3d73> * | demangler | 8 bytes | /Demangler/<lambda_01a7098693036236037e7cdb9bca3d73> *\n_EXCEPTION_DISPOSITION | excpt.h | 4 bytes | /excpt.h/_EXCEPTION_DISPOSITION\n";
        let types = parse_data_types(body);
        assert_eq!(types.len(), 3);
        assert_eq!(
            types[2],
            DataTypeEntry {
                name: "_EXCEPTION_DISPOSITION".into(),
                category: "excpt.h".into(),
                size: Some(4),
                path: "/excpt.h/_EXCEPTION_DISPOSITION".into(),
            }
        );
        // A pointer variant is its own entry, star included in the name.
        assert_eq!(types[1].name, "<lambda_01a7098693036236037e7cdb9bca3d73> *");
    }

    #[test]
    fn test_data_types_variable_size_and_empty_sentinel() {
        // The server renders an unsized type as `variable` in the size slot
        // (DataTypeService.listDataTypes), and an empty result as a prose
        // line; neither is a record.
        let body = "some_void_like | / | variable bytes | /some_void_like\nNo data types found for category: nope\n";
        let types = parse_data_types(body);
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].size, None);
        assert!(parse_data_types("No data types found").is_empty());
    }

    #[test]
    fn test_parses_a_data_items_page() {
        // `GET /list_data_items?offset=0&limit=4` on the 6.x bridge, eqmain.dll.
        let body = "IMAGE_DOS_HEADER_180000000 @ 180000000 [IMAGE_DOS_HEADER] (128 bytes)\nDAT_180000080 @ 180000080 [IMAGE_RICH_HEADER] (152 bytes)\nIMAGE_SECTION_HEADER_180000228 @ 180000228 [IMAGE_SECTION_HEADER] (40 bytes)\n";
        let items = parse_data_items(body);
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0],
            DataItem {
                label: "IMAGE_DOS_HEADER_180000000".into(),
                address: 0x180000000,
                type_name: "IMAGE_DOS_HEADER".into(),
                length: 128,
            }
        );
        assert_eq!(items[1].label, "DAT_180000080");
    }

    #[test]
    fn test_data_items_accepts_the_singular_byte_unit() {
        // The server writes `1 byte` for one-byte items (ListingService).
        let items = parse_data_items("DAT_180000300 @ 180000300 [byte] (1 byte)");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].length, 1);
        // A page past the end is an empty body, not an error.
        assert!(parse_data_items("").is_empty());
    }

    #[test]
    fn test_parses_a_struct_layout() {
        // `GET /get_struct_layout?struct_name=IMAGE_DOS_HEADER` on the 6.x
        // bridge, eqmain.dll — verbatim, padding included.
        let body = "Structure: IMAGE_DOS_HEADER\nSize: 128 bytes\nAlignment: 1\n\nLayout:\nOffset | Size | Type | Name\n-------|------|------|-----\n     0 |    2 | char[2]              | e_magic\n     2 |    2 | word                 | e_cblp\n    60 |    4 | dword                | e_lfanew\n    64 |   64 | byte[64]             | e_program\n";
        let layout = parse_struct_layout(body).expect("layout should parse");
        assert_eq!(layout.name, "IMAGE_DOS_HEADER");
        assert_eq!(layout.size, 128);
        assert_eq!(layout.alignment, 1);
        assert_eq!(layout.fields.len(), 4);
        assert_eq!(
            layout.fields[0],
            StructFieldLayout {
                offset: 0,
                size: 2,
                type_name: "char[2]".into(),
                field_name: "e_magic".into(),
            }
        );
        assert_eq!(layout.fields[3].field_name, "e_program");
        assert_eq!(layout.fields[3].offset, 64);
    }

    #[test]
    fn test_struct_layout_sentinels_parse_to_none() {
        // The 6.x bridge answers misses as prose, not as {"error": ...}, so
        // the parser must refuse them for the client to raise an error.
        assert!(parse_struct_layout("Structure not found: NoSuchStructXyz").is_none());
        assert!(parse_struct_layout("Data type is not a structure: someEnum").is_none());
        assert!(parse_struct_layout("Struct name is required").is_none());
    }

    #[test]
    fn test_parses_enum_values() {
        // `GET /get_enum_values?enum_name=_EXCEPTION_DISPOSITION` on the 6.x
        // bridge, eqmain.dll.
        let body = "Enumeration: _EXCEPTION_DISPOSITION\nSize: 4 bytes\n\nValues:\nName | Value\n-----|------\nExceptionContinueExecution | 0 (0x0)\nExceptionContinueSearch | 1 (0x1)\nExceptionNestedException | 2 (0x2)\nExceptionCollidedUnwind | 3 (0x3)\n";
        let definition = parse_enum_values(body).expect("enum should parse");
        assert_eq!(definition.name, "_EXCEPTION_DISPOSITION");
        assert_eq!(definition.size, 4);
        assert_eq!(definition.members.len(), 4);
        assert_eq!(definition.members[0].name, "ExceptionContinueExecution");
        assert_eq!(definition.members[0].value, 0);
        assert_eq!(definition.members[3].value, 3);
    }

    #[test]
    fn test_enum_values_sentinels_parse_to_none() {
        assert!(parse_enum_values("Enumeration not found: NoSuchEnumXyz").is_none());
        assert!(parse_enum_values("Data type is not an enumeration: someStruct").is_none());
        assert!(parse_enum_values("Enum name is required").is_none());
    }
}
