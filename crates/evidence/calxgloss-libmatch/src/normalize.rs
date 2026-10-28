//! Body normalization: the wildcards that make a body shape comparable.
//!
//! A signature matches the *normalized* decompiled body, not the raw
//! text. The parts of a decompile that change between builds,
//! decompiler versions, and neighboring functions all collapse to
//! fixed wildcard tokens: the variable names the decompiler invents
//! (Ghidra's `uVar1`, `param_2`, Kuna's `v1`, `a0`), register
//! temporaries (`in_EAX`, `unaff_RBX`), and the addresses that move
//! with the image layout (`DAT_180045a68`, `dat_293099630`,
//! `label_2930944d0`, `0x180045a68`). What survives is the shape:
//! calls, operators, constants, string literals, and control-flow
//! keywords — the parts a library routine spells the same way every
//! time it is compiled.
//!
//! The fold is a **dialect layer**. Each decompiler's invented
//! spellings are a dialect of the same body shape, and every dialect
//! folds its names, globals, and addresses onto the same tokens below.
//! One signature therefore speaks the shape whichever decompiler
//! emitted it. Ghidra's families arrived with the scan; Kuna's join
//! them here (issue #309, its corpus the fixture-target decompiles),
//! never as a second rule.
//!
//! What the dialect layer deliberately does *not* fold: names the
//! decompiler carried from the binary's own debug information (a Kuna
//! body's `width`, `stream->precision`, a `b` parameter) and function
//! names (`FUN_…`, `sub_…`). Those carry source facts, not invented
//! spellings. A signature that claims a shape written through
//! source-named operands is the operator-supplied database's territory,
//! not the starter set's.
//!
//! This is the corpus-wide rule for what "same body shape" means. The
//! known-library scan matches its signatures against this shape.
//! Other crates — the binary-version diff's pairing, in the
//! body-equivalence family — consume the very same entry point instead
//! of carrying their own normalizer. One shared rule, one owner.
//!
//! Normalization is never tested directly — signatures and scan
//! findings are the test surface — but its contract is documented here
//! because the built-in signatures and the downstream consumers are
//! both hand-authored against it.

use regex::Regex;
use std::sync::LazyLock;

/// The token every invented variable name collapses to: Ghidra's
/// `uVar1`/`iVar2`-family temporaries, `param_N` parameters, `local_N`
/// stack slots, register temporaries (`in_EAX`, `unaff_RBX`,
/// `extraout_ECX`, `register0x00000007`), and `CONCAT` joins, and
/// Kuna's `v1`-family temporaries, `a0`-family parameters, and `b_00`
/// flag temporaries — all of them spellings the decompiler picks for
/// the same register or slot, not facts about the source.
pub const VARIABLE_TOKEN: &str = "VAR";

/// The token every named program-data reference collapses to: Ghidra's
/// `DAT_180045a68` and Kuna's `dat_293099630` spellings of a global,
/// whose name is its address and so moves with every rebuild.
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

/// Ghidra's and Kuna's spellings of a named program-data address: the
/// `DAT_…`/`dat_…` form whose name is the address itself.
static DATA_SYMBOLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:DAT|dat)_[0-9a-fA-F]+").expect("the DAT_/dat_ pattern is a valid regex")
});

/// A hex literal long enough to be an image address rather than a
/// constant. Five hex digits is the floor — just under the smallest
/// typical image base — so sizes, offsets, and masks keep their value.
static ADDRESS_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b0x[0-9a-fA-F]{5,}\b").expect("the address-literal pattern is a valid regex")
});

/// Kuna's spelling of a jump target by address (`label_2930944d0`):
/// like the `DAT_`/`dat_` globals, the name is the address and moves
/// with every rebuild, so it folds to the address token rather than
/// standing as a name.
static LABEL_SYMBOLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blabel_[0-9a-fA-F]+\b").expect("the label_ pattern is a valid regex")
});

/// Kuna's invented names, in the spellings its decompiler emits: the
/// `v1`-family temporaries (one per register or slot, exactly the role
/// Ghidra's `uVar1` fills), the `a0`-family parameters, and the `b_00`
/// flag temporaries. Names Kuna carried from the binary's debug
/// information (`width`, `s`, `stream`) are deliberately *not* here:
/// they are source facts, not decompiler spellings, and folding
/// arbitrary source identifiers would fold call targets and fields
/// with them.
static KUNA_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[av][0-9]+|b_[0-9]+)\b").expect("the Kuna-name pattern is a valid regex")
});

/// Normalize the body line by line, keeping each original line paired
/// with its normalized form. The matcher matches against the
/// normalized shape but quotes the original line as a finding's
/// evidence.
///
/// Each line has its shifting spellings replaced with the wildcard
/// tokens above and its whitespace collapsed, so a signature reads
/// line by line against a body whose indentation and spacing the
/// decompiler changed. Function names (`FUN_…`) and called names stand
/// as written: a call target is part of the shape, and a signature
/// that wants to speak of the scanned function itself uses the
/// `{name}` placeholder rather than the raw name. String literals are
/// protected: the text inside double quotes is copied through
/// untouched, so a signature's wildcards never rewrite a literal the
/// routine carries.
///
/// This is the shared normalizer's public entry point: the shape it
/// produces is what "same body shape" means corpus-wide. A cross-crate
/// consumer pairs bodies through this function without re-testing the
/// normalization contract, which stays pinned here through the scan's
/// findings.
pub fn normalize_lines(body: &str) -> Vec<(String, String)> {
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
        let labeled = LABEL_SYMBOLS.replace_all(&addressed, ADDRESS_TOKEN);
        let ghidra_named = GHIDRA_NAMES.replace_all(&labeled, VARIABLE_TOKEN);
        let replaced = KUNA_NAMES.replace_all(&ghidra_named, VARIABLE_TOKEN);
        out.push_str(&replaced);
    }
    // Trim and collapse whitespace runs: the decompiler's indentation
    // and spacing are not part of the shape.
    out.split_whitespace().collect::<Vec<&str>>().join(" ")
}
