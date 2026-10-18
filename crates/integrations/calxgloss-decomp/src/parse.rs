//! Parsers for the engine's decompiled pseudo-C — the Ghidra-shaped text
//! dialect the engine reproduces (Kuna is a Ghidra port and emits the same
//! `FUN_…`/`WARNING` shapes, issue #214).
//!
//! Every other read answers from the engine already structured, so what
//! stays here is the scraper over the decompiler text: the one answer whose
//! real signature has to be recovered from the body itself. Anything
//! unparseable is skipped rather than guessed at: a half-understood address
//! is worse than a missing record, because it would silently produce a wrong
//! call target.

use crate::model::DecompiledFunction;

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
/// The signature is the first non-blank, non-comment line — joined with the
/// lines below it if Ghidra wrapped it — and the pseudo-C follows. The two
/// are separated at the `{` that opens the body, which is usually on its own
/// line but can share the signature's.
///
/// A long signature comes back wrapped, with the return type alone above the
/// name (often after a leading `/* WARNING: ... */` comment), so candidate
/// lines are joined until the declarator's `(` or the body's `{` shows up.
pub fn parse_decompiled(text: &str) -> Option<DecompiledFunction> {
    let mut signature = String::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("/*") && !l.starts_with("//"))
    {
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(line);
        if signature.contains('(') || signature.contains('{') {
            break;
        }
    }

    // A body brace on the signature line is not part of the declarator, and
    // leaving it there would make the signature unparseable as a C declaration.
    let signature = match signature.find('{') {
        Some(idx) => signature[..idx].trim_end().to_string(),
        None => signature,
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
        signature,
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

/// A decompiler's prefixes for a function it has no real name for, in either
/// engine's spelling: Ghidra's uppercase `FUN_`/`LAB_`/`SUB_`, or Kuna's
/// lowercase `sub_` (its unnamed functions are `sub_<addr>`).
fn is_decompiler_default_name(ident: &str) -> bool {
    ident.starts_with("FUN_")
        || ident.starts_with("LAB_")
        || ident.starts_with("SUB_")
        || ident.starts_with("sub_")
}

/// Default-named identifiers on `line` that are applied to an argument list.
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
            if is_decompiler_default_name(ident) {
                out.push(ident);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fixtures below are verbatim bodies captured from GhidraMCP 1.4 with
    // `eqmain.dll` open, and from Kuna's own listings. They are the contract:
    // if the engine's dialect changes, these are what must change with it.

    #[test]
    fn test_parses_decompiled_output() {
        // `GET /decompile_function?address=0x18008ed50`
        let body = "\nlonglong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return param_1 + ((longlong)param_2 + 4) * 8;\n}\n";
        let f = parse_decompiled(body).expect("should parse");
        assert_eq!(f.name, "FUN_18008ed50");
        // The signature is the one thing the metadata answers get wrong, so
        // recovering it from the body is the reason this parser exists.
        assert_eq!(
            f.signature,
            "longlong FUN_18008ed50(longlong param_1,int param_2)"
        );
        assert!(f.body.contains("return param_1"));
    }

    #[test]
    fn test_parses_a_signature_ghidra_wrapped_onto_multiple_lines() {
        // `GET /decompile_function?address=0x1800042e0` — Ghidra wraps long
        // signatures, and the leading WARNING comment leaves the return type
        // alone on its own line above the name.
        let body = "/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */\n\nundefined8 *\nFUN_1800042e0(undefined8 *param_1,undefined8 param_2)\n\n{\n  return *param_1;\n}\n";
        let f = parse_decompiled(body).expect("should parse");
        assert_eq!(f.name, "FUN_1800042e0");
        assert_eq!(
            f.signature,
            "undefined8 * FUN_1800042e0(undefined8 *param_1,undefined8 param_2)"
        );
        assert_eq!(f.parameter_names(), vec!["param_1", "param_2"]);
        assert!(f.body.contains("return *param_1"));
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
    fn test_scrapes_kuna_default_names_from_a_kuna_body() {
        // Kuna names its unnamed functions `sub_<addr>`, lowercase; the
        // scraper has to read that spelling too.
        let body = "undefined8 sub_140002490(undefined8 param_1)\n{\n  sub_1400025a0(param_1);\n  uVar2 = sub_1400026b0(local_10);\n  sub_1400025a0(param_1);\n}\n";
        assert_eq!(
            callees_from_decompiled(body),
            vec!["sub_1400025a0", "sub_1400026b0"]
        );
    }
}
