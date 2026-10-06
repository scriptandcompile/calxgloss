//! Hybrid string-to-function mapping.
//!
//! The mapper ties the program's strings to the functions that use them
//! through two sources, in the order the scan reaches them:
//!
//! - [`extract_strings_from_body`](HybridXrefMapper::extract_strings_from_body)
//!   reads a decompiled body directly — string literals, `DAT_xxxxxxxx`
//!   references resolved against the program's string table, and calls to
//!   recognized format functions.
//! - [`extract_strings_from_xrefs`](HybridXrefMapper::extract_strings_from_xrefs)
//!   consumes the Ghidra client's already-parsed xref records from
//!   `get_xrefs_to`, the fallback for functions whose body parse found
//!   nothing.
//!
//! The hybrid rule keeps the two apart per function: a function whose
//! body parse found strings gets no xref lookups. Where both sources do
//! report the same string, [`merge_usages`](HybridXrefMapper::merge_usages)
//! deduplicates by address and value and keeps the body-parsed
//! provenance, and the [`StringSource`] on each usage records how the tie
//! was made so confidence can follow it — 70 body-parsed, 60 xref-only,
//! the sync crate's precedent.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use calxgloss_ghidra::{StringLiteral, Xref};
use regex::Regex;

use crate::types::StringSource;

/// Confidence for a string tied to a function through its decompiled body.
pub const BODY_CONFIDENCE: u8 = 70;

/// Confidence for a string tied to a function only by an xref lookup.
pub const XREF_CONFIDENCE: u8 = 60;

/// One string tied to one function, with the line or xref that shows the
/// tie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedString {
    /// The function the string is tied to, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The address the string is defined at, or 0 when the body carries
    /// the literal inline and the string table names no address for it.
    pub string_address: u64,
    /// The string's contents.
    pub string_value: String,
    /// Whether the tie came from the body parse or an xref lookup.
    pub source: StringSource,
    /// The decompiled line or xref rendering that shows the use.
    pub evidence: String,
}

/// One format-function call read out of a decompiled body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatCall {
    /// The function the call sits in, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The format function called, e.g. `sprintf`.
    pub format_function: String,
    /// The decompiled call line itself.
    pub call_site: String,
    /// The format string passed to the call.
    pub format_string: String,
    /// The address the format string is defined at, or 0 when the body
    /// carries it inline.
    pub string_address: u64,
}

/// A format function and the argument position its format string sits at.
#[derive(Debug, Clone)]
struct FormatFunction {
    name: &'static str,
    /// 0-based index among the call's arguments.
    format_arg: usize,
}

/// The format functions the mapper recognizes, with where each call
/// carries its format string.
fn default_format_functions() -> Vec<FormatFunction> {
    vec![
        FormatFunction {
            name: "sprintf",
            format_arg: 1,
        },
        FormatFunction {
            name: "snprintf",
            format_arg: 1,
        },
        FormatFunction {
            name: "_snprintf",
            format_arg: 1,
        },
        FormatFunction {
            name: "sprintf_s",
            format_arg: 1,
        },
        FormatFunction {
            name: "wsprintf",
            format_arg: 1,
        },
        FormatFunction {
            name: "wsprintfA",
            format_arg: 1,
        },
        FormatFunction {
            name: "wsprintfW",
            format_arg: 1,
        },
        FormatFunction {
            name: "printf",
            format_arg: 0,
        },
        FormatFunction {
            name: "wprintf",
            format_arg: 0,
        },
        FormatFunction {
            name: "fprintf",
            format_arg: 1,
        },
    ]
}

/// The quoted-string-or-`DAT_` token scan, quote-aware: the alternation
/// consumes a whole quoted span before any `DAT_` lookalike inside it
/// can be seen, so a body line like `printf("DAT_180127cd8");` yields the
/// literal and no phantom reference.
fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""((?:[^"\\]|\\.)*)"|\bDAT_([0-9a-fA-F]{4,16})\b"#).expect("static pattern")
    })
}

/// Turns a decompiled literal's inner text into the string's value,
/// resolving the escapes the decompiler writes.
fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Maps the program's strings to the functions that use them, through
/// body parsing with an xref fallback.
///
/// The mapper holds no per-scan state beyond the format-function list, so
/// one instance serves a whole scan; the scan hands it each function's
/// body and the program's string table.
#[derive(Debug, Clone)]
pub struct HybridXrefMapper {
    format_functions: Vec<FormatFunction>,
}

impl Default for HybridXrefMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridXrefMapper {
    /// A mapper recognizing the standard format functions.
    pub fn new() -> Self {
        Self {
            format_functions: default_format_functions(),
        }
    }

    /// A mapper recognizing exactly `names` as format functions, each
    /// carrying its format string at the usual argument position.
    pub fn with_format_functions(names: &[&'static str]) -> Self {
        let defaults = default_format_functions();
        Self {
            format_functions: names
                .iter()
                .map(|name| {
                    defaults
                        .iter()
                        .find(|f| f.name == *name)
                        .cloned()
                        .unwrap_or(FormatFunction {
                            name,
                            format_arg: 1,
                        })
                })
                .collect(),
        }
    }

    /// Read the string uses out of one decompiled body.
    ///
    /// Recognizes direct literals, `DAT_xxxxxxxx` references resolved
    /// against `string_table` by address (a `DAT_` the table names no
    /// string for is not a string use and is skipped), and — through
    /// [`extract_format_calls`](Self::extract_format_calls) — format
    /// function calls. Usages are deduplicated by address and value,
    /// keeping the first line that showed each, and every usage carries
    /// [`BodyParse`](StringSource::BodyParse) provenance.
    pub fn extract_strings_from_body(
        &self,
        function: &str,
        body: &str,
        string_table: &HashMap<u64, String>,
    ) -> Vec<MappedString> {
        let by_value = index_by_value(string_table);
        let mut usages = Vec::new();
        let mut seen: HashSet<(u64, String)> = HashSet::new();
        for line in body.lines() {
            for captures in token_re().captures_iter(line) {
                let usage = if let Some(inner) = captures.get(1) {
                    let value = unescape(inner.as_str());
                    let address = by_value.get(value.as_str()).copied().unwrap_or(0);
                    MappedString {
                        function: function.to_string(),
                        string_address: address,
                        string_value: value,
                        source: StringSource::BodyParse,
                        evidence: line.trim().to_string(),
                    }
                } else if let Some(hex) = captures.get(2) {
                    let Ok(address) = u64::from_str_radix(hex.as_str(), 16) else {
                        continue;
                    };
                    let Some(value) = string_table.get(&address) else {
                        // A DAT_ the string table names no string for is
                        // some other data reference, not a string use.
                        continue;
                    };
                    MappedString {
                        function: function.to_string(),
                        string_address: address,
                        string_value: value.clone(),
                        source: StringSource::BodyParse,
                        evidence: line.trim().to_string(),
                    }
                } else {
                    continue;
                };
                if seen.insert((usage.string_address, usage.string_value.clone())) {
                    usages.push(usage);
                }
            }
        }
        usages
    }

    /// Read the format-function calls out of one decompiled body.
    ///
    /// A call counts when it names a recognized format function and its
    /// format-string argument is a direct literal or a `DAT_` the string
    /// table resolves; an argument held in a variable is not a format
    /// string the scan can read, and the call is skipped.
    pub fn extract_format_calls(
        &self,
        function: &str,
        body: &str,
        string_table: &HashMap<u64, String>,
    ) -> Vec<FormatCall> {
        let by_value = index_by_value(string_table);
        let mut calls = Vec::new();
        for line in body.lines() {
            for format_function in &self.format_functions {
                let Some(call_start) = find_call(line, format_function.name) else {
                    continue;
                };
                let Some(args) = split_arguments(&line[call_start..]) else {
                    continue;
                };
                let Some(arg) = args.get(format_function.format_arg) else {
                    continue;
                };
                let arg = arg.trim();
                let (format_string, string_address) = if let Some(inner) = quoted_inner(arg) {
                    let value = unescape(inner);
                    let address = by_value.get(value.as_str()).copied().unwrap_or(0);
                    (value, address)
                } else if let Some(hex) = dat_reference(arg) {
                    let Ok(address) = u64::from_str_radix(hex, 16) else {
                        continue;
                    };
                    match string_table.get(&address) {
                        Some(value) => (value.clone(), address),
                        None => continue,
                    }
                } else {
                    continue;
                };
                calls.push(FormatCall {
                    function: function.to_string(),
                    format_function: format_function.name.to_string(),
                    call_site: line.trim().to_string(),
                    format_string,
                    string_address,
                });
            }
        }
        calls
    }

    /// Turn one string's xref records into per-function usages.
    ///
    /// The Ghidra client has already parsed `get_xrefs_to`'s response;
    /// each xref that names an enclosing function ties that function to
    /// `string`, with the xref rendering as evidence and
    /// [`Xref`](StringSource::Xref) provenance.
    pub fn extract_strings_from_xrefs(
        &self,
        string: &StringLiteral,
        xrefs: &[Xref],
    ) -> Vec<MappedString> {
        xrefs
            .iter()
            .filter_map(|xref| {
                let function = xref.function.as_ref()?;
                Some(MappedString {
                    function: function.clone(),
                    string_address: string.address,
                    string_value: string.value.clone(),
                    source: StringSource::Xref,
                    evidence: format!("From {}", xref.to_line()),
                })
            })
            .collect()
    }

    /// Merge the two sources' usages for one function, deduplicating by
    /// address and value.
    ///
    /// The hybrid rule means `xref_usages` is normally empty whenever
    /// `body_usages` is not — the scan only asks for xrefs when the body
    /// parse found nothing — but a string reported by both still collapses
    /// to one usage, keeping the body-parsed provenance.
    pub fn merge_usages(
        body_usages: Vec<MappedString>,
        xref_usages: Vec<MappedString>,
    ) -> Vec<MappedString> {
        let mut merged = Vec::new();
        let mut seen: HashSet<(u64, String)> = HashSet::new();
        for usage in body_usages.into_iter().chain(xref_usages) {
            if seen.insert((usage.string_address, usage.string_value.clone())) {
                merged.push(usage);
            }
        }
        merged
    }
}

/// Index the string table by value for direct-literal lookups, taking the
/// lowest address when several addresses carry the same value.
fn index_by_value(string_table: &HashMap<u64, String>) -> HashMap<&str, u64> {
    let mut by_value: HashMap<&str, u64> = HashMap::new();
    let mut entries: Vec<(&u64, &String)> = string_table.iter().collect();
    entries.sort_by_key(|(address, _)| **address);
    for (address, value) in entries {
        by_value.entry(value.as_str()).or_insert(*address);
    }
    by_value
}

/// The offset just past `name(` when a call to it starts at a word
/// boundary in `line`.
fn find_call(line: &str, name: &str) -> Option<usize> {
    let mut search = 0;
    while let Some(offset) = line[search..].find(name) {
        let start = search + offset;
        let after = start + name.len();
        let boundary_before = start == 0
            || !line.as_bytes()[start - 1].is_ascii_alphanumeric()
                && line.as_bytes()[start - 1] != b'_';
        let rest = line[after..].trim_start();
        if boundary_before && rest.starts_with('(') {
            let open = after + (line[after..].len() - rest.len());
            return Some(open + 1);
        }
        search = after;
    }
    None
}

/// Split a call's argument list — `line` starting just past the `(` — on
/// top-level commas, respecting nested parentheses and quoted spans.
fn split_arguments(line: &str) -> Option<Vec<String>> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut args = Vec::new();
    let mut current = String::new();
    for c in line.chars() {
        if in_string {
            current.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                current.push(c);
            }
            '(' => {
                depth += 1;
                current.push(c);
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    if !current.trim().is_empty() {
                        args.push(current.trim().to_string());
                    }
                    return Some(args);
                }
                current.push(c);
            }
            ',' if depth == 1 => {
                args.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    None
}

/// The inner text of `arg` when it is a whole quoted literal.
fn quoted_inner(arg: &str) -> Option<&str> {
    arg.strip_prefix('"')?.strip_suffix('"')
}

/// The hex digits of `arg` when it is a whole `DAT_xxxxxxxx` reference.
fn dat_reference(arg: &str) -> Option<&str> {
    arg.strip_prefix("DAT_")
        .filter(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> HashMap<u64, String> {
        HashMap::from([
            (0x180127cd8, "Everquest".to_string()),
            (
                0x180128cf0,
                "********** Chat logging turned OFF.".to_string(),
            ),
            (0x180129a00, "%s: %d hits".to_string()),
        ])
    }

    #[test]
    fn a_direct_literal_in_the_body_is_a_string_use() {
        let mapper = HybridXrefMapper::new();
        let body = "  lFile = CreateFileA(\"Journal.txt\",0xc0000000,0,0,3,0x80,0);";
        let usages = mapper.extract_strings_from_body("FUN_18003ab00", body, &table());
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].string_value, "Journal.txt");
        assert_eq!(usages[0].string_address, 0);
        assert_eq!(usages[0].source, StringSource::BodyParse);
        assert!(usages[0].evidence.contains("CreateFileA"));
    }

    #[test]
    fn a_direct_literal_takes_its_address_from_the_string_table() {
        let mapper = HybridXrefMapper::new();
        let body = "  pcVar1 = \"Everquest\";";
        let usages = mapper.extract_strings_from_body("FUN_18003ab00", body, &table());
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].string_address, 0x180127cd8);
    }

    #[test]
    fn a_dat_reference_resolves_against_the_string_table_by_address() {
        let mapper = HybridXrefMapper::new();
        let body = "  puVar3 = (uint *)DAT_180128cf0;";
        let usages = mapper.extract_strings_from_body("FUN_180006da0", body, &table());
        assert_eq!(usages.len(), 1);
        assert_eq!(
            usages[0].string_value,
            "********** Chat logging turned OFF."
        );
        assert_eq!(usages[0].string_address, 0x180128cf0);
    }

    #[test]
    fn a_dat_reference_the_table_names_no_string_for_is_not_a_string_use() {
        let mapper = HybridXrefMapper::new();
        let body = "  uVar1 = *(uint *)DAT_180140000;";
        let usages = mapper.extract_strings_from_body("FUN_180006da0", body, &table());
        assert!(usages.is_empty());
    }

    #[test]
    fn a_dat_lookalike_inside_a_quoted_span_invents_no_string() {
        let mapper = HybridXrefMapper::new();
        let body = "  printf(\"DAT_180128cf0 is not a reference\");";
        let usages = mapper.extract_strings_from_body("FUN_180006da0", body, &table());
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].string_value, "DAT_180128cf0 is not a reference");
        assert_eq!(usages[0].string_address, 0);
    }

    #[test]
    fn a_body_repeats_of_one_string_collapse_to_one_usage() {
        let mapper = HybridXrefMapper::new();
        let body =
            "  pcVar1 = \"Journal.txt\";\n  lFile = CreateFileA(\"Journal.txt\",0,0,0,3,0,0);";
        let usages = mapper.extract_strings_from_body("FUN_18003ab00", body, &table());
        assert_eq!(usages.len(), 1);
        assert!(usages[0].evidence.contains("pcVar1"));
    }

    #[test]
    fn a_format_function_call_is_read_with_its_format_string() {
        let mapper = HybridXrefMapper::new();
        let body = "  sprintf(local_10, \"%s: %d hits\", pcVar2, uVar3);";
        let calls = mapper.extract_format_calls("FUN_18003ab00", body, &table());
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].format_function, "sprintf");
        assert_eq!(calls[0].format_string, "%s: %d hits");
        assert_eq!(calls[0].string_address, 0x180129a00);
        assert!(calls[0].call_site.contains("sprintf"));
    }

    #[test]
    fn a_format_string_behind_a_dat_reference_is_resolved() {
        let mapper = HybridXrefMapper::new();
        let body = "  wsprintfA(local_20, DAT_180129a00, local_30, local_34);";
        let calls = mapper.extract_format_calls("FUN_18003ab00", body, &table());
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].format_function, "wsprintfA");
        assert_eq!(calls[0].format_string, "%s: %d hits");
    }

    #[test]
    fn a_format_argument_held_in_a_variable_is_not_a_readable_format_string() {
        let mapper = HybridXrefMapper::new();
        let body = "  sprintf(local_10, pcFormat, pcVar2);";
        let calls = mapper.extract_format_calls("FUN_18003ab00", body, &table());
        assert!(calls.is_empty());
    }

    #[test]
    fn a_name_that_only_contains_a_format_function_is_not_a_call() {
        let mapper = HybridXrefMapper::new();
        // `my_sprintf_helper` contains `sprintf` but calls no format function.
        let body = "  my_sprintf_helper(local_10, \"x\");";
        let calls = mapper.extract_format_calls("FUN_18003ab00", body, &table());
        assert!(calls.is_empty());
    }

    #[test]
    fn xref_records_become_usages_with_xref_provenance() {
        let mapper = HybridXrefMapper::new();
        let string = StringLiteral {
            address: 0x180128cf0,
            value: "********** Chat logging turned OFF.".to_string(),
        };
        let xrefs = vec![
            Xref {
                address: 0x180006f04,
                function: Some("FUN_180006da0".to_string()),
                kind: Some("DATA".to_string()),
            },
            Xref {
                address: 0x180007a10,
                function: None,
                kind: Some("DATA".to_string()),
            },
        ];
        let usages = mapper.extract_strings_from_xrefs(&string, &xrefs);
        assert_eq!(usages.len(), 1, "an xref naming no function ties nothing");
        assert_eq!(usages[0].function, "FUN_180006da0");
        assert_eq!(usages[0].source, StringSource::Xref);
        assert_eq!(usages[0].string_address, 0x180128cf0);
        assert_eq!(
            usages[0].evidence,
            "From 0x180006f04 in FUN_180006da0 [DATA]"
        );
    }

    #[test]
    fn merging_collapses_a_string_both_sources_report_onto_the_body_usage() {
        let body_usage = MappedString {
            function: "FUN_18003ab00".to_string(),
            string_address: 0x180127cd8,
            string_value: "Everquest".to_string(),
            source: StringSource::BodyParse,
            evidence: "pcVar1 = \"Everquest\";".to_string(),
        };
        let xref_usage = MappedString {
            function: "FUN_18003ab00".to_string(),
            string_address: 0x180127cd8,
            string_value: "Everquest".to_string(),
            source: StringSource::Xref,
            evidence: "From 0x180006f04 in FUN_18003ab00 [DATA]".to_string(),
        };
        let merged = HybridXrefMapper::merge_usages(vec![body_usage], vec![xref_usage]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, StringSource::BodyParse);
    }

    #[test]
    fn the_hybrid_rule_leaves_xref_usages_out_when_the_body_parse_found_strings() {
        // The scan asks for xrefs only when the body parse came back
        // empty; the mapper's merge keeps that rule visible in the
        // provenance either way.
        let mapper = HybridXrefMapper::new();
        let body = "  pcVar1 = \"Everquest\";";
        let body_usages = mapper.extract_strings_from_body("FUN_18003ab00", body, &table());
        assert!(!body_usages.is_empty());
        let merged = HybridXrefMapper::merge_usages(body_usages, Vec::new());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, StringSource::BodyParse);
    }

    #[test]
    fn confidence_follows_the_sync_precedent() {
        assert_eq!(BODY_CONFIDENCE, 70);
        assert_eq!(XREF_CONFIDENCE, 60);
    }
}
