//! Body normalization: the wildcards that make a body shape comparable.
//!
//! A signature matches the *normalized* decompiled body, not the raw
//! text: the parts of a Ghidra decompile that vary between builds,
//! decompiler versions, and neighboring functions — the variable names
//! Ghidra invents (`uVar1`, `param_2`), register temporaries (`in_EAX`,
//! `unaff_RBX`), and the addresses that shift with the image layout
//! (`DAT_180045a68`, `0x180045a68`) — all collapse to fixed wildcard
//! tokens. What survives is the shape: calls, operators, constants,
//! string literals, and control-flow keywords, the parts a library
//! routine spells the same way every time it is compiled.
//!
//! Normalization is never tested directly — signatures and scan
//! findings are the test surface — but its contract is documented here
//! because the built-in signatures are hand-authored against it.

use regex::Regex;
use std::sync::LazyLock;

/// The token every Ghidra-invented variable name collapses to: the
/// `uVar1`/`iVar2`-family temporaries, the `param_N` parameters, the
/// `local_N` stack slots, the register temporaries (`in_EAX`,
/// `unaff_RBX`, `extraout_ECX`, `register0x00000007`), and the `CONCAT`
/// joins — all of them spellings the decompiler picks for the same
/// register or slot, not facts about the source.
pub const VARIABLE_TOKEN: &str = "VAR";

/// The token every named program-data reference collapses to: Ghidra's
/// `DAT_180045a68` spelling of a global, whose name is its address and
/// so moves with every rebuild.
pub const DATA_TOKEN: &str = "DATA";

/// The token every address-shaped hex literal collapses to: a `0x…`
/// constant long enough to be a pointer into the image (`0x180045a68`),
/// which the linker moves. Short constants — sizes, offsets, masks, the
/// `0x20` of a `malloc(0x20)` — are *not* address-shaped and stand as
/// written: they are part of the routine's shape.
pub const ADDRESS_TOKEN: &str = "ADDR";

/// Ghidra's invented names, in the spellings its decompiler emits.
static GHIDRA_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:[a-z]{1,6}Var[0-9]+|local_[0-9a-fA-F]+|param_[0-9]+|in_[A-Za-z0-9_]+|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|register0x[0-9a-fA-F]+|CONCAT[0-9a-fA-F]{2,4}_[0-9a-fA-F]+)\b",
    )
    .expect("the Ghidra-name pattern is a valid regex")
});

/// Ghidra's `DAT_` spelling of a named program-data address.
static DATA_SYMBOLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bDAT_[0-9a-fA-F]+").expect("the DAT_ pattern is a valid regex"));

/// A hex literal long enough to be an image address rather than a
/// constant. Five digits is the floor: the smallest value a typical
/// image base reaches, so sizes and offsets keep their value.
static ADDRESS_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b0x[0-9a-fA-F]{5,}\b").expect("the address-literal pattern is a valid regex")
});

/// Normalize the body keeping the pairing to the original lines, so a
/// matcher can report an evidence line from the body as decompiled
/// while still matching against the normalized shape. The normalized
/// form is the shape a signature matches; the original line is what a
/// finding quotes as evidence.
///
/// Each line has its volatile spellings replaced with the wildcard
/// tokens above and its whitespace collapsed, so a signature reads line
/// by line against a body whose indentation and spacing the decompiler
/// changed. Function names (`FUN_…`) and called names stand as written:
/// a call target is part of the shape, and a signature that wants to
/// speak of the scanned function itself uses the `{name}` placeholder
/// rather than the raw name. String literals are protected: the text
/// inside double quotes is copied through untouched, so a signature's
/// wildcards never rewrite a literal the routine carries.
pub(crate) fn normalize_lines(body: &str) -> Vec<(String, String)> {
    body.lines()
        .map(|line| {
            let normalized = normalize_line(line);
            (line.trim().to_string(), normalized)
        })
        .collect()
}

/// Normalize one line, protecting double-quoted string literals from
/// the wildcard substitutions.
fn normalize_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    // Split on double quotes: even segments are code, odd segments are
    // string literals copied through verbatim.
    for (index, segment) in line.split('"').enumerate() {
        if index % 2 == 1 {
            out.push('"');
            out.push_str(segment);
            continue;
        }
        let dataless = DATA_SYMBOLS.replace_all(segment, DATA_TOKEN);
        let addressed = ADDRESS_LITERALS.replace_all(&dataless, ADDRESS_TOKEN);
        let replaced = GHIDRA_NAMES.replace_all(&addressed, VARIABLE_TOKEN);
        out.push_str(&replaced);
    }
    // Trim and collapse whitespace runs: the decompiler's indentation
    // and spacing are not part of the shape.
    out.split_whitespace().collect::<Vec<&str>>().join(" ")
}
