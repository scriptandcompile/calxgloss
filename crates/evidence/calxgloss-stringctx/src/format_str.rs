//! Format-string parsing and specifier→Rust-type inference.
//!
//! A format string is the one place a decompiled call states its own
//! argument types: `"%s: %d hits"` says the call passed a string and an
//! integer. This module reads the specifiers out of a format string and
//! maps each to the Rust type the original argument read as, so the
//! translator sees `*const i8` and `i32` where the pseudo-C shows only
//! bare variables.
//!
//! [`extract_format_hints`] does the reading; the mapping table it consults
//! is documented on [`rust_type_for`] and [`FormatStringEngine`] carries it
//! as the engine the scan configures.

use crate::types::FormatHint;
use regex::Regex;
use std::sync::OnceLock;

/// One entry of the specifier→Rust-type table: a conversion character, an
/// optional length modifier, and the Rust type the pair reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecifierType {
    /// The conversion character, e.g. `s` in `%s`.
    pub conversion: char,
    /// The length modifier, e.g. `l` in `%ld`; empty for the plain form.
    pub modifier: &'static str,
    /// The Rust type the argument reads as, e.g. `*const i8`.
    pub rust_type: &'static str,
}

/// The documented specifier→Rust-type table.
///
/// The plain conversions carry the types the spec names — `%s` →
/// `*const i8`, `%d`/`%i` → `i32`, `%u` → `u32`, `%x`/`%X` → `u32`,
/// `%f` → `f32`, `%c` → `i8`, `%p` → `*const c_void` — and the length
/// modifiers widen to the sized forms: `%ld` → `i64`, `%lu`/`%lx` → `u64`,
/// `%lf` → `f64`. A precision does not change the type, so `%.2f` reads as
/// `f32` like `%f`.
///
/// The remaining floating conversions (`e`, `E`, `g`, `G`, `a`, `A`) follow
/// the `%f` rule — plain `f32`, `l`/`L`-modified `f64` — and `n` writes
/// through a pointer, reading as `*mut i32`. A conversion the table does
/// not name is **not guessed at**: it takes the documented default,
/// `*const c_void`, the same way the sync crate defaults an unrecognized
/// atomic width to one documented type rather than a per-call guess.
/// `%%` is a literal percent and takes no argument slot at all.
pub const SPECIFIER_TYPES: &[SpecifierType] = &[
    SpecifierType {
        conversion: 's',
        modifier: "",
        rust_type: "*const i8",
    },
    SpecifierType {
        conversion: 'd',
        modifier: "",
        rust_type: "i32",
    },
    SpecifierType {
        conversion: 'i',
        modifier: "",
        rust_type: "i32",
    },
    SpecifierType {
        conversion: 'u',
        modifier: "",
        rust_type: "u32",
    },
    SpecifierType {
        conversion: 'x',
        modifier: "",
        rust_type: "u32",
    },
    SpecifierType {
        conversion: 'X',
        modifier: "",
        rust_type: "u32",
    },
    SpecifierType {
        conversion: 'f',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'F',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'e',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'E',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'g',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'G',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'a',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'A',
        modifier: "",
        rust_type: "f32",
    },
    SpecifierType {
        conversion: 'c',
        modifier: "",
        rust_type: "i8",
    },
    SpecifierType {
        conversion: 'p',
        modifier: "",
        rust_type: "*const c_void",
    },
    SpecifierType {
        conversion: 'n',
        modifier: "",
        rust_type: "*mut i32",
    },
    // Length-modified forms.
    SpecifierType {
        conversion: 'd',
        modifier: "l",
        rust_type: "i64",
    },
    SpecifierType {
        conversion: 'i',
        modifier: "l",
        rust_type: "i64",
    },
    SpecifierType {
        conversion: 'd',
        modifier: "ll",
        rust_type: "i64",
    },
    SpecifierType {
        conversion: 'i',
        modifier: "ll",
        rust_type: "i64",
    },
    SpecifierType {
        conversion: 'u',
        modifier: "l",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'u',
        modifier: "ll",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'x',
        modifier: "l",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'x',
        modifier: "ll",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'X',
        modifier: "l",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'X',
        modifier: "ll",
        rust_type: "u64",
    },
    SpecifierType {
        conversion: 'f',
        modifier: "l",
        rust_type: "f64",
    },
    SpecifierType {
        conversion: 'f',
        modifier: "L",
        rust_type: "f64",
    },
    SpecifierType {
        conversion: 'e',
        modifier: "l",
        rust_type: "f64",
    },
    SpecifierType {
        conversion: 'g',
        modifier: "l",
        rust_type: "f64",
    },
    SpecifierType {
        conversion: 'c',
        modifier: "l",
        rust_type: "u32",
    },
    SpecifierType {
        conversion: 's',
        modifier: "l",
        rust_type: "*const u16",
    },
];

/// The documented default for a conversion the table does not name.
pub const UNKNOWN_TYPE: &str = "*const c_void";

/// The Rust type a specifier's argument reads as, per the documented table.
///
/// `specifier` is the full spelling as written — `%s`, `%.2f`, `%ld` — and
/// the length modifier and conversion character are read off its end. A
/// conversion outside the table takes [`UNKNOWN_TYPE`]; `%%` has no type
/// because it takes no argument.
pub fn rust_type_for(specifier: &str) -> &'static str {
    // Peel the conversion character, then the longest matching length
    // modifier in front of it.
    let Some(conversion) = specifier.chars().next_back() else {
        return UNKNOWN_TYPE;
    };
    let stem = &specifier[..specifier.len() - conversion.len_utf8()];
    for modifier in ["ll", "hh", "l", "h", "L", "z", "j", "t"] {
        if stem.ends_with(modifier) {
            if let Some(entry) = SPECIFIER_TYPES
                .iter()
                .find(|e| e.conversion == conversion && e.modifier == modifier)
            {
                return entry.rust_type;
            }
            // A modifier the table does not pair with this conversion
            // (e.g. `%hu`) still reads through the plain form: the
            // narrower C type arrives promoted.
            return SPECIFIER_TYPES
                .iter()
                .find(|e| e.conversion == conversion && e.modifier.is_empty())
                .map_or(UNKNOWN_TYPE, |e| e.rust_type);
        }
    }
    SPECIFIER_TYPES
        .iter()
        .find(|e| e.conversion == conversion && e.modifier.is_empty())
        .map_or(UNKNOWN_TYPE, |e| e.rust_type)
}

/// The shape of one `printf`-style specifier: `%`, flags, optional width,
/// optional precision, optional length modifier, conversion character.
fn specifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"%[-+ #0]*(?:[0-9]+)?(?:\.[0-9]+)?(?:ll|hh|l|h|L|z|j|t)?[a-zA-Z]")
            .expect("static pattern")
    })
}

/// Parse the format specifiers out of a format string into [`FormatHint`]
/// records, in argument order.
///
/// Each hint carries the specifier's full spelling, its 0-based argument
/// position, and the Rust type [`rust_type_for`] assigns. `%%` is a
/// literal percent: it is skipped and takes no position. Text outside
/// specifiers is ignored.
pub fn extract_format_hints(format: &str) -> Vec<FormatHint> {
    let mut hints = Vec::new();
    let mut position = 0usize;
    let mut cursor = 0usize;
    // Walk percent to percent. A `%%` pair prints a literal percent and
    // consumes no argument, and its second half must never be re-read as
    // the start of a specifier — otherwise `"100%% done: %d"` would read
    // `"% d"` (space flag + `d`) before the real `"%d"`.
    while let Some(offset) = format[cursor..].find('%') {
        let start = cursor + offset;
        if format.as_bytes().get(start + 1) == Some(&b'%') {
            cursor = start + 2;
            continue;
        }
        if let Some(match_) = specifier_re().find_at(format, start)
            && match_.start() == start
        {
            hints.push(FormatHint {
                specifier: match_.as_str().to_string(),
                position,
                rust_type: rust_type_for(match_.as_str()).to_string(),
            });
            position += 1;
            cursor = match_.end();
            continue;
        }
        // A stray percent that starts no specifier at all.
        cursor = start + 1;
    }
    hints
}

/// The format-string engine the scan configures: it fills [`FormatHint`]
/// records from a format string and renders the summaries the prompt
/// consumes.
///
/// The engine carries the documented table on [`SPECIFIER_TYPES`] and holds
/// no per-scan state, so one instance serves a whole scan.
#[derive(Debug, Clone, Default)]
pub struct FormatStringEngine;

impl FormatStringEngine {
    /// An engine scanning with the documented specifier table.
    pub fn new() -> Self {
        Self
    }

    /// Parse `format`'s specifiers into [`FormatHint`] records, in
    /// argument order (`%%` taking no slot).
    pub fn extract_hints(&self, format: &str) -> Vec<FormatHint> {
        extract_format_hints(format)
    }

    /// Render a hint list as the argument-type summary the prompt shows,
    /// e.g. `` `*const i8`, `i32` ``. An empty list reads as no arguments.
    pub fn summarize(&self, hints: &[FormatHint]) -> String {
        summarize_hints(hints)
    }
}

/// Render a hint list as the argument-type summary the prompt shows,
/// e.g. `` `*const i8`, `i32` ``. An empty list reads as no arguments.
///
/// This is the free form of [`FormatStringEngine::summarize`], so the
/// finding's own [`suggestion`](crate::types::StringFinding::suggestion)
/// renders the same summary the engine does.
pub fn summarize_hints(hints: &[FormatHint]) -> String {
    if hints.is_empty() {
        return "no format arguments".to_string();
    }
    hints
        .iter()
        .map(|hint| format!("`{}`", hint.rust_type))
        .collect::<Vec<_>>()
        .join(", ")
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hints(format: &str) -> Vec<(String, usize, String)> {
        extract_format_hints(format)
            .into_iter()
            .map(|h| (h.specifier, h.position, h.rust_type))
            .collect()
    }

    #[test]
    fn a_plain_format_string_yields_its_argument_types_in_order() {
        assert_eq!(
            hints("%s: %d hits"),
            vec![
                ("%s".into(), 0, "*const i8".into()),
                ("%d".into(), 1, "i32".into()),
            ]
        );
    }

    #[test]
    fn every_table_specifier_maps_as_documented() {
        assert_eq!(rust_type_for("%s"), "*const i8");
        assert_eq!(rust_type_for("%d"), "i32");
        assert_eq!(rust_type_for("%i"), "i32");
        assert_eq!(rust_type_for("%u"), "u32");
        assert_eq!(rust_type_for("%ld"), "i64");
        assert_eq!(rust_type_for("%lu"), "u64");
        assert_eq!(rust_type_for("%x"), "u32");
        assert_eq!(rust_type_for("%X"), "u32");
        assert_eq!(rust_type_for("%f"), "f32");
        assert_eq!(rust_type_for("%.2f"), "f32");
        assert_eq!(rust_type_for("%lf"), "f64");
        assert_eq!(rust_type_for("%c"), "i8");
        assert_eq!(rust_type_for("%p"), "*const c_void");
    }

    #[test]
    fn flags_width_and_precision_travel_with_the_specifier_but_not_its_type() {
        assert_eq!(hints("%-10.3f"), vec![("%-10.3f".into(), 0, "f32".into())]);
        assert_eq!(hints("%08x"), vec![("%08x".into(), 0, "u32".into())]);
    }

    #[test]
    fn a_double_percent_is_a_literal_and_takes_no_argument() {
        assert_eq!(
            hints("100%% done: %d"),
            vec![("%d".into(), 0, "i32".into())]
        );
    }

    #[test]
    fn an_unknown_conversion_takes_the_documented_default() {
        // The table does not name `%q`; it is defaulted, not guessed.
        assert_eq!(rust_type_for("%q"), UNKNOWN_TYPE);
        assert_eq!(hints("%q"), vec![("%q".into(), 0, "*const c_void".into())]);
    }

    #[test]
    fn a_format_string_without_specifiers_yields_no_hints() {
        assert!(hints("Journal.txt").is_empty());
        assert!(hints("").is_empty());
    }

    #[test]
    fn the_engine_fills_hints_and_renders_the_summary() {
        let engine = FormatStringEngine::new();
        let hints = engine.extract_hints("%s took %d ms");
        assert_eq!(hints.len(), 2);
        assert_eq!(engine.summarize(&hints), "`*const i8`, `i32`");
        assert_eq!(engine.summarize(&[]), "no format arguments");
    }
}
