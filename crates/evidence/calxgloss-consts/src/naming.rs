//! Context-derived naming for repeated literals.
//!
//! The frequency pass already reads every decompiled body to tally its
//! literals; this module reads the same bodies for the one fact the
//! tally throws away — *which identifier sits beside the literal*. When
//! a repeated literal is assigned to or compared against a named
//! variable (`size = 0x280`, `mode == 3`), the bodies plainly say what
//! the value is, and the constant gains a name derived from that
//! identifier — `SIZE_0x280` — instead of the mechanical
//! `VALUE_0x280` the tally alone could offer.
//!
//! The reading is pure and adds no engine reads: [`context_names`]
//! walks the shared tokenizer's stream over one body and reports, in
//! body order, each literal an assignment or comparison names. The
//! engine keeps the first qualifying sighting per value across the
//! whole scan, so naming is deterministic and two scans of one program
//! name their constants identically.
//!
//! The naming gate is the honesty rule: Ghidra's placeholder spellings —
//! `local_10`, `uVar1`, `FUN_`, `DAT_`, `param_1`, a bare letter plus
//! digits — name nothing, because the decompiler minted them. A name
//! only ever rides on an identifier that actually means something.

use crate::tokenize::{TokenKind, tokenize};

/// The names one body's assignments and comparisons give its literals.
///
/// Each entry is the literal value and the derived constant name — the
/// adjacent identifier uppercased with the value appended, so `size =
/// 0x280` yields `SIZE_0x280`. Entries come out in body order, one per
/// value: the first qualifying sighting of a value wins, and later
/// sightings of the same value name nothing further.
pub(crate) fn context_names(body: &str) -> Vec<(u64, String)> {
    let tokens = tokenize(body);
    let mut names: Vec<(u64, String)> = Vec::new();
    for window in tokens.windows(3) {
        let (left, op, right) = (&window[0], &window[1], &window[2]);
        // An identifier on one side of an assignment or comparison and
        // a literal on the other: the body says what the value is.
        // Only `=` reads left-to-right — `0x280 = size` is not a shape
        // pseudo-C spells — while `==` and `!=` read from either side.
        let named = match (&left.kind, &op.kind, &right.kind) {
            (TokenKind::Ident(name), TokenKind::Punct(op), TokenKind::Int(value))
                if matches!(*op, "=" | "==" | "!=") =>
            {
                Some((*name, *value))
            }
            (TokenKind::Int(value), TokenKind::Punct("==" | "!="), TokenKind::Ident(name)) => {
                Some((*name, *value))
            }
            _ => None,
        };
        if let Some((identifier, value)) = named {
            if is_placeholder(identifier) {
                continue; // a decompiler-minted name says nothing about the value
            }
            if names.iter().any(|(seen, _)| *seen == value) {
                continue; // the first qualifying sighting of a value wins
            }
            names.push((value, constant_name(identifier, value)));
        }
    }
    names
}

/// Whether an identifier is one of Ghidra's placeholder spellings,
/// minted for something the decompiler could not name — a stack slot
/// (`local_10`), an undefined variable (`uVar1`, `iVar2`, `bVar3`,
/// `sVar4`), a parameter (`param_1`), a nameless function (`FUN_…`) or
/// global (`DAT_…`), or a bare letter plus digits (`a1`). None of them
/// carries meaning the scan could hang a constant name on, so they
/// never name one; a real identifier — `size`, `mode`, even a bare `x`
/// a human left behind — passes.
fn is_placeholder(identifier: &str) -> bool {
    if ["local_", "param_", "FUN_", "DAT_"]
        .iter()
        .any(|prefix| identifier.starts_with(prefix))
    {
        return true;
    }
    // The `<letter>Var<digits>` undefined-variable family: uVar1,
    // iVar2, bVar3, sVar4, fVar5, …
    let Some(first) = identifier.chars().next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    if identifier[1..].starts_with("Var") {
        // Strictly the `<letter>Var<digits>` shape Ghidra mints — a real
        // word like `aVariable` starts with a letter + "Var" but is not
        // a placeholder.
        let rest = &identifier[4..];
        return !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit());
    }
    // A bare letter followed by only digits: a1, x2, u9. A lone letter
    // (`x`) is a real name, not a placeholder.
    identifier.len() > 1 && identifier[1..].bytes().all(|c| c.is_ascii_digit())
}

/// The constant name a body's identifier gives one of its literals:
/// the identifier uppercased with the value appended, so `size` and
/// `0x280` spell `SIZE_0x280`. Carrying the value in the name keeps
/// two values assigned to the same identifier — `size = 0x280` and
/// `size = 0x400` — from claiming one constant name.
fn constant_name(identifier: &str, value: u64) -> String {
    format!("{}_{value:#x}", identifier.to_uppercase())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_assignment_names_the_constant() {
        assert_eq!(
            context_names("  size = 0x280;\n"),
            vec![(0x280, "SIZE_0x280".to_string())]
        );
    }

    #[test]
    fn a_comparison_names_the_constant() {
        assert_eq!(
            context_names("  if (mode == 3) {\n    dispatch();\n  }\n"),
            vec![(3, "MODE_0x3".to_string())]
        );
        assert_eq!(
            context_names("  if (code != 0xdead) {\n    return;\n  }\n"),
            vec![(0xdead, "CODE_0xdead".to_string())]
        );
        // A comparison reads from either side of the operator.
        assert_eq!(
            context_names("  if (0x280 == flag) {\n    return;\n  }\n"),
            vec![(0x280, "FLAG_0x280".to_string())]
        );
    }

    #[test]
    fn decompiler_placeholder_identifiers_never_name_a_constant() {
        // Every spelling here is one the decompiler minted — a stack
        // slot, an undefined variable, a nameless function or global, a
        // parameter — so none of them says anything about the value.
        let body = "  local_10 = 0x280;\n\
                    \x20 uVar1 = 0x281;\n\
                    \x20 iVar2 = 0x282;\n\
                    \x20 bVar3 = 0x283;\n\
                    \x20 sVar4 == 0x284;\n\
                    \x20 DAT_180040000 = 0x285;\n\
                    \x20 param_1 = 0x286;\n\
                    \x20 FUN_18003ab00 = 0x287;\n";
        assert_eq!(context_names(body), Vec::<(u64, String)>::new());
    }

    #[test]
    fn a_single_letter_plus_digits_never_names_a_constant() {
        // Ghidra's short minted spellings (`a1`, `x2`) name nothing any
        // more than the long ones; a real one-letter name (`x`) does.
        assert_eq!(
            context_names("  a1 = 0x280;\n  x2 == 0x281;\n"),
            Vec::<(u64, String)>::new()
        );
        assert_eq!(
            context_names("  x = 0x280;\n"),
            vec![(0x280, "X_0x280".to_string())]
        );
    }

    #[test]
    fn a_real_word_that_happens_to_start_like_a_var_placeholder_names() {
        // `aVariable` begins with a letter + "Var", but it is not the
        // Ghidra `<letter>Var<digits>` spelling — it carries meaning, so
        // it names.
        assert_eq!(
            context_names("  aVariable = 0x280;\n"),
            vec![(0x280, "AVARIABLE_0x280".to_string())]
        );
    }

    #[test]
    fn the_first_qualifying_sighting_of_a_value_wins() {
        // Two named sightings of one value: the first in body order
        // names it, the second says nothing further, and the value is
        // named exactly once.
        assert_eq!(
            context_names("  size = 0x280;\n  count = 0x280;\n"),
            vec![(0x280, "SIZE_0x280".to_string())]
        );
    }

    #[test]
    fn call_arguments_name_no_constant() {
        // A literal handed across a call is an argument, not an
        // assignment or comparison — `copy(dst, 0x280)` says `dst` is a
        // buffer and nothing about 0x280.
        assert_eq!(
            context_names("  copy(dst, 0x280);\n  reserve(0x280);\n"),
            Vec::<(u64, String)>::new()
        );
    }

    #[test]
    fn two_scans_of_the_same_body_name_identically() {
        // Naming is a pure walk of a deterministic token stream, so the
        // same body names its constants the same way every time — two
        // scans of one program diff cleanly.
        let body = "  size = 0x280;\n  if (mode == 3) { dispatch(); }\n  local_8 = 0x10;\n";
        assert_eq!(context_names(body), context_names(body));
    }
}
