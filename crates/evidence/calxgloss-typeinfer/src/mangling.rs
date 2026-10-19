//! C++ mangling analysis: the type contract carried in a name.
//!
//! When a name visible in the decompiled output or the listing spells out
//! a signature — a demangled qualified call like `Widget::Render(int,
//! char *)`, or an MSVC-mangled symbol like `?Render@Widget@@QAEXH@Z` —
//! the contract is already in the name, and no body usage says more than
//! the symbol does. [`ManglingDetector`] reads both spellings:
//!
//! - **the listing's own symbols** — an MSVC-mangled name decodes for
//!   calling convention (a member's implicit `this`), argument count, and
//!   rough argument types, typing the function that carries the name even
//!   when its body proves nothing: the unnamed wrapper typed from its own
//!   symbol;
//! - **names inside a body** — the analyzed function's own demangled name
//!   with a spelled parameter list, placed against its decompiled
//!   parameters, and qualified calls whose callee carries one
//!   (`Widget::Render(int,char*)(param_1, uVar2)`), placed against the
//!   call's argument count.
//!
//! Every reading lands as a parameter (or return) record under
//! [`InferenceMethod::Mangling`] at [`MANGLING_CONFIDENCE`] — a
//! symbol-borne fact, above the usage-inference families and below the
//! vtable/COM dispatch evidence — keyed by the name as spelled, with the
//! name itself or the call line as evidence. A name that carries no
//! parameter list produces nothing, and namespace noise (`std::`,
//! `operator`) is never mistaken for a member contract — the
//! this-pointer detector's qualified-chain handling is prior art for
//! that guard.
//!
//! The MSVC decoder covers the practical subset: simple integer, float,
//! `bool`, and `wchar_t` arguments, near and 64-bit pointers to them,
//! pointers to and by-value class/struct types, and the member
//! conventions. Anything outside the subset — references, function
//! pointers, enums, templates, operator spellings, name back-references
//! — makes the name unparseable, and an unparseable name produces no
//! records at all rather than a partial guess.

use crate::types::{
    CallingConvention, InferenceMethod, InferenceScope, InferredParamType, InferredReturnType,
    InferredType,
};
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{closing_paren, is_ident_byte, line_at, skip_string, skip_ws};

/// Confidence of a reading the name itself carries: the symbol spells the
/// contract, so it outranks every usage-inference family (known-signature
/// 75, cross-function 65–70, assignment-chain and return-usage 60) and
/// sits just below the dispatch evidence that proves a `this` pointer
/// structurally (vtable 85–90, COM 88).
const MANGLING_CONFIDENCE: u8 = 80;

/// Qualified-name segments that mark library or operator plumbing rather
/// than a class of the analyzed program — the same whole-segment guard the
/// this-pointer detector applies to qualified chains (`NAMESPACE_NOISE`
/// in [`crate::this_ptr`]): a `std::` library member or an `operator`
/// spelling names no member contract for a parameter.
const NAMESPACE_NOISE: [&str; 2] = ["std", "operator"];

/// Whether a decoded class chain is namespace noise rather than a class of
/// the analyzed program — any whole segment named `std` or `operator`.
/// Shared with [`crate::convention`]: a mangled `std::` member names
/// library plumbing, so neither the parameter readings nor the convention
/// reading should come from it.
pub(crate) fn is_namespace_noise(class: Option<&str>) -> bool {
    class.is_some_and(|class| class.split("::").any(|s| NAMESPACE_NOISE.contains(&s)))
}

/// Assemble one name-borne parameter reading into its record: the
/// mangling method, function scope — the contract belongs to the named
/// function — and the name or call line as evidence.
fn param_record(
    function: &str,
    param_index: usize,
    param_name: Option<String>,
    inferred_type: &str,
    evidence: &str,
) -> InferredType {
    InferredType::Param(InferredParamType {
        function: function.to_string(),
        param_index,
        param_name,
        inferred_type: inferred_type.to_string(),
        method: InferenceMethod::Mangling,
        scope: InferenceScope::Function,
        confidence: MANGLING_CONFIDENCE.into(),
        evidence: evidence.to_string(),
    })
}

/// Assemble one name-borne return reading into its record.
fn return_record(function: &str, inferred_type: &str, evidence: &str) -> InferredType {
    InferredType::Return(InferredReturnType {
        function: function.to_string(),
        inferred_type: inferred_type.to_string(),
        method: InferenceMethod::Mangling,
        scope: InferenceScope::Function,
        confidence: MANGLING_CONFIDENCE.into(),
        evidence: evidence.to_string(),
    })
}

// ============================================================
// MSVC-mangled symbols
// ============================================================

/// The signature an MSVC-mangled function symbol decodes to.
pub(crate) struct MsvcSignature {
    /// The qualified class chain, outermost first (`Outer::Inner`), when
    /// the symbol names a member.
    pub(crate) class: Option<String>,
    /// Whether the encoding passes an implicit `this` as argument zero
    /// — any non-static member, whatever the convention letter spells.
    implicit_this: bool,
    /// The calling convention the name's convention letter declares;
    /// `None` for a letter outside the closed set (a Pascal-spelled `B`).
    pub(crate) convention: Option<CallingConvention>,
    /// The return type as C text; `None` when the symbol spells `void`,
    /// which narrows nothing.
    return_type: Option<String>,
    /// The argument types as C text, in order; empty for a `void` list.
    args: Vec<String>,
}

/// Decode an MSVC-mangled function name, or nothing when the name is not
/// mangled or carries a shape outside the practical subset.
///
/// The shape is `?name@Class@@<class><qualifiers><convention><return><args>`:
/// the simple name, an optional class chain (innermost first, reversed
/// here into `Outer::Inner`), then the property letters — the function
/// class (`Y`/`Z` free, the static-member codes `C D K L S T`, the plain
/// member codes `A B E F I J M N Q R U V`), a non-static member's
/// qualifiers (a 64-bit-`this` `E`, restrict/unaligned/ref letters, and a
/// const/volatile letter), and the calling convention. A member that is
/// not static carries the implicit `this` at argument zero, whatever the
/// convention letter spells — an x64 member decorates `A` and still
/// takes one.
pub(crate) fn parse_msvc(name: &str) -> Option<MsvcSignature> {
    let bytes = name.as_bytes();
    if bytes.first() != Some(&b'?') {
        return None;
    }
    let mut i = 1usize;

    // The simple name, up to the first `@`. An empty name or an operator
    // spelling (`??2@YAPAXI@Z`) carries no readable contract.
    let name_start = i;
    while i < bytes.len() && bytes[i] != b'@' {
        i += 1;
    }
    let simple = &name[name_start..i];
    if simple.is_empty() || simple.starts_with('?') {
        return None;
    }

    // The class chain: `@@` right after the name spells a free function;
    // otherwise segments run innermost-first until the closing `@@`.
    let mut class: Option<String> = None;
    if bytes.get(i) != Some(&b'@') {
        return None; // `?name` with no property section is not a function symbol
    }
    i += 1;
    if bytes.get(i) == Some(&b'@') {
        i += 1;
    } else {
        let mut segments: Vec<&str> = Vec::new();
        loop {
            let start = i;
            while i < bytes.len() && bytes[i] != b'@' {
                i += 1;
            }
            if i == start || i >= bytes.len() || !is_plain_segment(&name[start..i]) {
                return None;
            }
            segments.push(&name[start..i]);
            i += 1; // the `@` ending the segment
            match bytes.get(i) {
                Some(&byte) if is_ident_byte(byte) || byte == b'~' => continue,
                Some(&b'@') => {
                    i += 1;
                    break;
                }
                _ => return None,
            }
        }
        segments.reverse();
        class = Some(segments.join("::"));
    }

    // The property letters: the function class — free (`Y`/`Z`), a
    // static member (no implicit `this`), or a plain member (implicit
    // `this` at argument zero). Thunk classes (`G H O P W X`, each
    // followed by an adjustment count) and anything else carry no
    // readable contract.
    let implicit_this = match bytes.get(i)? {
        b'Y' | b'Z' => false,
        b'C' | b'D' | b'K' | b'L' | b'S' | b'T' => false,
        b'A' | b'B' | b'E' | b'F' | b'I' | b'J' | b'M' | b'N' | b'Q' | b'R' | b'U' | b'V' => true,
        _ => return None,
    };
    i += 1;
    if implicit_this {
        // A non-static member's qualifiers: an optional `E` marking a
        // 64-bit `this`, optional restrict/unaligned and ref-qualifier
        // letters, and an optional const/volatile letter — none of
        // which change what the contract types.
        while matches!(bytes.get(i), Some(b'E' | b'I' | b'F' | b'G' | b'H')) {
            i += 1;
        }
        if matches!(bytes.get(i), Some(b'A'..=b'D' | b'Q'..=b'T')) {
            i += 1;
        }
    }
    // The convention letter, decoded into the closed set: `A` is cdecl,
    // `C`, `E`, and `G` thiscall (`G` the old EVC spelling), `I` stdcall.
    // `B` spells Pascal — outside the closed set, so the name still
    // decodes for types but carries no convention reading.
    let convention = match bytes.get(i)? {
        b'A' => Some(CallingConvention::Cdecl),
        b'B' => None,
        b'C' | b'E' | b'G' => Some(CallingConvention::Thiscall),
        b'I' => Some(CallingConvention::Stdcall),
        _ => return None,
    };
    i += 1;

    // The return type, then the argument types until the `Z` (or `@Z`)
    // that ends the decorated name.
    let return_type = parse_msvc_type(name, &mut i)?;
    let mut args: Vec<String> = Vec::new();
    loop {
        match bytes.get(i)? {
            b'Z' => {
                i += 1;
                break;
            }
            b'@' if bytes.get(i + 1) == Some(&b'Z') => {
                i += 2;
                break;
            }
            b'@' => i += 1, // argument separator after a qualified type
            _ => args.push(parse_msvc_type(name, &mut i)?),
        }
    }
    if i != bytes.len() {
        return None; // trailing junk: the name is not a clean symbol
    }
    let return_type = (return_type != "void").then_some(return_type);
    Some(MsvcSignature {
        class,
        implicit_this,
        convention,
        return_type,
        args,
    })
}

/// The next type code in `name` at `i`, advanced past it: the simple
/// scalar set, `_N`/`_W`/`_X`, pointers (`P` plus an attribute letter,
/// x86 near `A` or x64 `E`, over any decodable base), and class/struct
/// types by name (`V`/`U` plus the `@`-separated chain). Anything else —
/// references, function pointers, enums, templates — is outside the
/// subset and decodes to nothing.
fn parse_msvc_type(name: &str, i: &mut usize) -> Option<String> {
    let simple = |i: &mut usize, text: &str| {
        *i += 1;
        Some(text.to_string())
    };
    match *name.as_bytes().get(*i)? {
        b'X' => simple(i, "void"),
        b'D' => simple(i, "char"),
        b'C' => simple(i, "signed char"),
        b'E' => simple(i, "unsigned char"),
        b'F' => simple(i, "short"),
        b'G' => simple(i, "unsigned short"),
        b'H' => simple(i, "int"),
        b'I' => simple(i, "unsigned int"),
        b'J' => simple(i, "long long"),
        b'K' => simple(i, "unsigned long long"),
        b'M' => simple(i, "float"),
        b'N' => simple(i, "double"),
        b'_' => match *name.as_bytes().get(*i + 1)? {
            b'N' => {
                *i += 2;
                Some("bool".to_string())
            }
            b'W' => {
                *i += 2;
                Some("wchar_t".to_string())
            }
            b'X' => {
                *i += 2;
                Some("long double".to_string())
            }
            _ => None,
        },
        b'V' | b'U' => {
            *i += 1;
            parse_msvc_class_chain(name, i)
        }
        b'P' => {
            *i += 1;
            // The pointee: an optional 64-bit `E`, an optional
            // const/volatile/far storage letter, then the base type.
            // `P6` (pointer to function) and friends fall outside the
            // subset.
            if name.as_bytes().get(*i) == Some(&b'E') {
                *i += 1;
            }
            if matches!(name.as_bytes().get(*i), Some(b'A'..=b'D' | b'Q'..=b'T')) {
                *i += 1;
            }
            let base = parse_msvc_type(name, i)?;
            Some(format!("{base} *"))
        }
        _ => None,
    }
}

/// The `@`-separated class chain of a `V`/`U` type or a class-typed
/// argument, stored innermost-first and returned as `Outer::Inner`. The
/// chain ends at the `@` whose follower opens the next section.
fn parse_msvc_class_chain(name: &str, i: &mut usize) -> Option<String> {
    let bytes = name.as_bytes();
    let mut segments: Vec<&str> = Vec::new();
    loop {
        let start = *i;
        while *i < bytes.len() && bytes[*i] != b'@' {
            *i += 1;
        }
        if *i == start || *i >= bytes.len() || !is_plain_segment(&name[start..*i]) {
            return None;
        }
        segments.push(&name[start..*i]);
        *i += 1; // the `@` ending the segment
        match bytes.get(*i) {
            Some(&byte) if is_ident_byte(byte) || byte == b'~' => continue,
            Some(_) => break,
            None => return None,
        }
    }
    segments.reverse();
    Some(segments.join("::"))
}

// ============================================================
// Demangled qualified names
// ============================================================

/// The spelled parameter list of a demangled qualified name —
/// `Widget::Render(int, char *)` → `["int", "char *"]` — or nothing when
/// the name is not a qualified chain ending in one parenthesized group,
/// carries namespace noise, or holds an entry that is not a plain type
/// declaration (a template, a reference, an array, a named parameter).
fn demangled_parameter_list(name: &str) -> Option<Vec<String>> {
    let open = name.find('(')?;
    let close = closing_paren(name, open)?;
    if close != name.len() - 1 {
        return None; // the group must be the name's tail, not a middle span
    }
    let segments: Vec<&str> = name[..open].split("::").collect();
    if !is_clean_chain(&segments) {
        return None;
    }
    parse_demangled_params(&name[open + 1..close])
}

/// The comma-separated entries of a spelled parameter list, each parsed
/// as a type declaration; a lone `void` spells the empty list.
fn parse_demangled_params(text: &str) -> Option<Vec<String>> {
    let text = text.trim();
    if text.is_empty() || text == "void" {
        return Some(Vec::new());
    }
    let mut types = Vec::new();
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    loop {
        if i == text.len() || (bytes[i] == b',' && depth == 0) {
            types.push(parse_type_declaration(&text[start..i])?);
            if i == text.len() {
                break;
            }
            start = i + 1;
            i = start;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'<' => depth += 1,
            b')' | b']' | b'>' => depth = depth.checked_sub(1)?,
            _ => {}
        }
        i += 1;
    }
    Some(types)
}

/// Words that may stand beside another word in one declaration: a
/// multi-word entry is a primitive spelled with qualifiers (`unsigned
/// int`, `long long`, `signed char`), so every word must come from this
/// set. That is what separates `unsigned int` from `int width` — a named
/// parameter, which names no readable type.
const TYPE_WORDS: [&str; 12] = [
    "signed", "unsigned", "long", "short", "char", "int", "float", "double", "void", "struct",
    "union", "enum",
];

/// One parameter-list entry as C text: type words and pointer stars, with
/// `const` dropped from the reading (`char const *` → `char *`,
/// `unsigned int` → `unsigned int`, `Widget **` → `Widget **`). Anything
/// that is not a plain declaration — a template argument, a reference,
/// an array, a named parameter — names no readable type.
fn parse_type_declaration(entry: &str) -> Option<String> {
    let bytes = entry.as_bytes();
    let mut words: Vec<&str> = Vec::new();
    let mut stars = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'*' => {
                while i < bytes.len() && bytes[i] == b'*' {
                    i += 1;
                }
                stars += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                words.push(&entry[start..i]);
            }
            _ => return None,
        }
    }
    let words: Vec<&str> = words.into_iter().filter(|w| *w != "const").collect();
    if words.is_empty() {
        return None;
    }
    if words.len() > 1 && !words.iter().all(|w| TYPE_WORDS.contains(w)) {
        return None; // a second word that is not a type word names a parameter
    }
    let mut text = words.join(" ");
    for _ in 0..stars {
        text.push_str(" *");
    }
    Some(text)
}

/// Whether a qualified-chain segment is a plain name: identifier bytes
/// only, allowing a destructor's leading `~`. A segment carrying `$`,
/// digits up front, or template punctuation makes the whole name
/// unparseable.
fn is_plain_segment(segment: &str) -> bool {
    let core = segment.strip_prefix('~').unwrap_or(segment);
    let mut bytes = core.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {
            bytes.all(|b| is_ident_byte(b) || b == b'~')
        }
        None => false,
        _ => false,
    }
}

/// Whether a split name is a qualified chain the detector may read: at
/// least two plain segments, none of them namespace noise.
fn is_clean_chain(segments: &[&str]) -> bool {
    segments.len() >= 2
        && segments.iter().all(|s| is_plain_segment(s))
        && !segments.iter().any(|s| NAMESPACE_NOISE.contains(s))
}

/// A direct call to a qualified name — `a::b::method(...)`, a destructor
/// segment's leading `~` allowed — found in a body: the end of the callee
/// span and the `(` opening its first argument group. Prior art: the
/// this-pointer detector's [`crate::this_ptr`] chain walk.
fn qualified_chain(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut i = start;
    let mut end = start;
    let mut qualified = false;
    loop {
        let mut j = i;
        if bytes.get(j) == Some(&b'~') {
            j += 1;
        }
        while j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
        }
        if j == i || (bytes.get(i) == Some(&b'~') && j == i + 1) {
            break;
        }
        end = j;
        if bytes.get(j) == Some(&b':') && bytes.get(j + 1) == Some(&b':') {
            qualified = true;
            i = j + 2;
        } else {
            break;
        }
    }
    if !qualified {
        return None;
    }
    let open = skip_ws(bytes, end);
    (bytes.get(open) == Some(&b'(')).then_some((end, open))
}

/// The top-level argument count of the call group whose `(` sits at
/// `open` and whose `)` at `close`: one more than the depth-0 commas,
/// zero for an empty group.
fn count_arguments(body: &str, open: usize, close: usize) -> usize {
    let bytes = body.as_bytes();
    let inner = body[open + 1..close].trim();
    if inner.is_empty() {
        return 0;
    }
    let mut depth = 0usize;
    let mut commas = 0usize;
    let mut i = open + 1;
    while i < close {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' if depth == 0 => {
                commas += 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    commas + 1
}

// ============================================================
// Detector
// ============================================================

/// C++ mangling analysis over listing symbols and decompiled bodies.
///
/// The detector is stateless: every reading comes from the name or body
/// it is handed, so one detector serves an entire scan. It fetches
/// nothing itself — the engine hands it the listing names and the same
/// [`DecompiledFunction`] text every other inline detector reads, so the
/// scan stays at one decompile per function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManglingDetector;

impl ManglingDetector {
    /// A detector with the full reading set: MSVC-mangled listing symbols
    /// and demangled qualified names with spelled parameter lists.
    pub fn new() -> Self {
        Self
    }

    /// The records an MSVC-mangled listing symbol carries for the
    /// function that bears it, keyed by the symbol verbatim with the
    /// symbol itself as evidence: a member's implicit `this` at position
    /// zero (typed as the named class's pointer), then one parameter
    /// record per decoded argument, then a return record when the symbol
    /// spells a non-`void` return.
    ///
    /// A name that is not mangled, or whose encoding falls outside the
    /// practical subset, produces nothing — a half-decoded signature
    /// would mis-type positions the decoder is not sure of. The records
    /// carry no decompiled parameter names: the name is the evidence, and
    /// the prompt falls back to `param_N` positions.
    pub fn detect_from_listing(&self, name: &str) -> Vec<InferredType> {
        let Some(signature) = parse_msvc(name) else {
            return Vec::new();
        };
        // A mangled `std::` member names library plumbing, not a contract
        // of the analyzed program — the same whole-segment guard the
        // demangled path applies to qualified chains.
        if is_namespace_noise(signature.class.as_deref()) {
            return Vec::new();
        }
        let mut records = Vec::new();
        let mut index = 0usize;
        if signature.implicit_this
            && let Some(class) = &signature.class
        {
            records.push(param_record(name, index, None, &format!("{class} *"), name));
            index += 1;
        }
        for arg in &signature.args {
            // A lone `X` argument list spells "no parameters", not a
            // void-typed argument.
            if arg == "void" {
                continue;
            }
            records.push(param_record(name, index, None, arg, name));
            index += 1;
        }
        if let Some(return_type) = &signature.return_type {
            records.push(return_record(name, return_type, name));
        }
        records
    }

    /// The records a decompiled body carries in names: the analyzed
    /// function's own demangled name with a spelled parameter list, and
    /// every qualified call in the body whose callee carries one.
    ///
    /// A spelled list types the function it names only where its
    /// positions can be placed. For the analyzed function's own name,
    /// the decompiled signature places it: the list maps from position 0
    /// when the body declares as many parameters as the name lists, and
    /// from position 1 — past the implicit `this` — when it declares one
    /// more; any other mismatch places nothing. For a callee, the call's
    /// argument count places it: equal counts map from 0, one extra
    /// argument is the member's `this` (typed as the named class's
    /// pointer at position 0) with the list starting at 1; any other
    /// mismatch places nothing. A name without a parameter list — an
    /// ordinary `Widget::paint(param_1)` call — is not a contract the
    /// name carries, and produces nothing here (the this-pointer
    /// detector already reads what usage shows of it).
    pub fn detect_from_body(&self, func: &DecompiledFunction) -> Vec<InferredType> {
        let mut records = self.own_name_readings(func);
        records.extend(self.qualified_call_readings(func));
        records
    }

    /// The analyzed function's own demangled name, placed against its
    /// decompiled parameters. A mangled own name is the listing pass's
    /// reading, not a second one here.
    fn own_name_readings(&self, func: &DecompiledFunction) -> Vec<InferredType> {
        if func.name.starts_with('?') {
            return Vec::new();
        }
        let Some(types) = demangled_parameter_list(&func.name) else {
            return Vec::new();
        };
        let params = func.parameter_names();
        let offset = if params.len() == types.len() {
            0
        } else if params.len() == types.len() + 1 {
            1 // the member's implicit this: the name's list starts after it
        } else {
            return Vec::new();
        };
        types
            .iter()
            .enumerate()
            .map(|(position, inferred_type)| {
                param_record(
                    &func.name,
                    position + offset,
                    Some(params[position + offset].clone()),
                    inferred_type,
                    func.signature.trim(),
                )
            })
            .collect()
    }

    /// Every qualified call in the body whose callee carries a spelled
    /// parameter list — the name's group immediately followed by the
    /// call's own group, `Widget::Render(int,char*)(param_1, uVar2)` —
    /// read as [`call_contract`](Self::call_contract).
    fn qualified_call_readings(&self, func: &DecompiledFunction) -> Vec<InferredType> {
        let body = &func.body;
        let bytes = body.as_bytes();
        let mut records = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => i = skip_string(bytes, i + 1),
                b if b.is_ascii_alphabetic() || b == b'_' => {
                    if i > 0 && is_ident_byte(bytes[i - 1]) {
                        i += 1;
                        continue;
                    }
                    match qualified_chain(bytes, i) {
                        Some((end, open)) => {
                            if let Some(readings) = self.call_contract(body, i, end, open) {
                                records.extend(readings);
                            }
                            i = end;
                        }
                        None => {
                            let mut j = i;
                            while j < bytes.len() && is_ident_byte(bytes[j]) {
                                j += 1;
                            }
                            i = j;
                        }
                    }
                }
                _ => i += 1,
            }
        }
        records
    }

    /// The contract one qualified call spells, or nothing: the callee's
    /// first group must be a parameter list (a second group — the actual
    /// call — follows it), the chain must be a clean qualified name, and
    /// the call's argument count must place the list (equal counts, or
    /// one extra argument standing as the member's `this`). The records
    /// are keyed by the callee as spelled, name and list together, so
    /// they compete with the callee's own readings under the same name
    /// the listing carries; the call line is the evidence.
    fn call_contract(
        &self,
        body: &str,
        start: usize,
        end: usize,
        open: usize,
    ) -> Option<Vec<InferredType>> {
        let list_close = closing_paren(body, open)?;
        let bytes = body.as_bytes();
        let call_open = skip_ws(bytes, list_close + 1);
        if bytes.get(call_open) != Some(&b'(') {
            return None; // one group is an argument list, not a spelled contract
        }
        let segments: Vec<&str> = body[start..end].split("::").collect();
        if !is_clean_chain(&segments) {
            return None;
        }
        let types = parse_demangled_params(&body[open + 1..list_close])?;
        let call_close = closing_paren(body, call_open)?;
        let arguments = count_arguments(body, call_open, call_close);
        let offset = if arguments == types.len() {
            0
        } else if arguments == types.len() + 1 {
            1
        } else {
            return None; // name and site disagree; guessing positions mis-types
        };
        let key = &body[start..list_close + 1];
        let evidence = line_at(body, start);
        let mut records = Vec::new();
        if offset == 1 {
            let class = segments[..segments.len() - 1].join("::");
            records.push(param_record(key, 0, None, &format!("{class} *"), &evidence));
        }
        for (position, inferred_type) in types.iter().enumerate() {
            records.push(param_record(
                key,
                position + offset,
                None,
                inferred_type,
                &evidence,
            ));
        }
        Some(records)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Confidence;

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: signature.into(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    fn from_listing(name: &str) -> Vec<InferredType> {
        ManglingDetector::new().detect_from_listing(name)
    }

    fn from_body(func: &DecompiledFunction) -> Vec<InferredType> {
        ManglingDetector::new().detect_from_body(func)
    }

    fn params(records: &[InferredType]) -> Vec<(usize, String)> {
        records
            .iter()
            .filter_map(|record| match record {
                InferredType::Param(record) => {
                    Some((record.param_index, record.inferred_type.clone()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = ManglingDetector::new();
        assert_eq!(detector, ManglingDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven concurrently over a program's listing,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ManglingDetector>();
    }

    // ---- MSVC-mangled listing symbols ----

    #[test]
    fn a_mangled_member_symbol_types_this_and_its_arguments() {
        // `void Widget::load(char *)` in x64 mangling: public member
        // (`Q`) with a 64-bit `this` (`E`), cdecl (`AA`), void return
        // (`X`), one 64-bit char-pointer argument (`PEAD`).
        let records = from_listing("?load@Widget@@QEAAXPEAD@Z");
        assert_eq!(
            params(&records),
            vec![(0, "Widget *".into()), (1, "char *".into())]
        );
        let InferredType::Param(record) = &records[1] else {
            unreachable!("the symbol emits parameter records");
        };
        assert_eq!(record.function, "?load@Widget@@QEAAXPEAD@Z");
        assert_eq!(record.param_name, None);
        assert_eq!(record.method, InferenceMethod::Mangling);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(MANGLING_CONFIDENCE));
        assert_eq!(record.evidence, "?load@Widget@@QEAAXPEAD@Z");
    }

    #[test]
    fn a_mangled_symbol_with_a_non_void_return_types_the_return() {
        // `char *Widget::copy(const char *)`: return `PEAD`, argument
        // `PEBD` (const char pointer) — the const rides off the reading.
        let records = from_listing("?copy@Widget@@QEAAPEADPEBD@Z");
        assert_eq!(
            params(&records),
            vec![(0, "Widget *".into()), (1, "char *".into())]
        );
        let InferredType::Return(record) = records
            .last()
            .expect("a non-void symbol emits a return record")
        else {
            unreachable!("the symbol emits a return record");
        };
        assert_eq!(record.function, "?copy@Widget@@QEAAPEADPEBD@Z");
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::Mangling);
        assert_eq!(record.confidence, Confidence::new(MANGLING_CONFIDENCE));
    }

    #[test]
    fn a_static_member_symbol_carries_no_this() {
        // `S` spells a static member: the contract takes no implicit
        // this, so the spelled argument starts at position 0, and the
        // void return narrows nothing.
        let records = from_listing("?create@Widget@@SAXPAVBrush@@@Z");
        assert_eq!(params(&records), vec![(0, "Brush *".into())]);
    }

    #[test]
    fn a_free_function_symbol_types_only_its_arguments() {
        // `int __cdecl compare(int, unsigned int)`: free (`Y`), int
        // return, `H` and `I` arguments.
        let records = from_listing("?compare@@YAHHI@Z");
        assert_eq!(
            params(&records),
            vec![(0, "int".into()), (1, "unsigned int".into())]
        );
        let InferredType::Return(record) = records
            .last()
            .expect("a non-void symbol emits a return record")
        else {
            unreachable!("the symbol emits a return record");
        };
        assert_eq!(record.inferred_type, "int");
    }

    #[test]
    fn the_argument_set_decodes_convention_count_and_rough_types() {
        // `__thiscall` x86 member: `QAE` public member, void return,
        // int / bool / void-pointer / wchar_t-pointer arguments, and the
        // `@`-separated class chain naming the this pointer.
        let records = from_listing("?setup@UdpRefCount@UdpLibrary@@QAEXH_NPAXPA_W@Z");
        assert_eq!(
            params(&records),
            vec![
                (0, "UdpLibrary::UdpRefCount *".into()),
                (1, "int".into()),
                (2, "bool".into()),
                (3, "void *".into()),
                (4, "wchar_t *".into()),
            ]
        );
    }

    #[test]
    fn a_void_argument_list_and_void_return_type_nothing_extra() {
        // `void Widget::paint(void)`: the lone `X` argument spells no
        // parameters, and the void return narrows nothing.
        let records = from_listing("?paint@Widget@@QAEXXZ");
        assert_eq!(params(&records), vec![(0, "Widget *".into())]);
        assert!(
            !records
                .iter()
                .any(|record| matches!(record, InferredType::Return(_))),
            "a void return is not a narrowing"
        );
    }

    #[test]
    fn an_unparseable_symbol_produces_no_records() {
        // A function-pointer argument (`P6`), a reference (`AE`), and a
        // template spelling all fall outside the subset: the whole name
        // decodes to nothing rather than a partial guess.
        assert!(from_listing("?cb@Widget@@QAEP6GXZ@Z").is_empty());
        assert!(from_listing("?ref@Widget@@QEAAXAEAH@Z").is_empty());
        assert!(from_listing("??2@YAPAXI@Z").is_empty()); // operator new
        assert!(from_listing("FUN_18003ab00").is_empty()); // not mangled at all
    }

    // ---- demangled names in bodies ----

    #[test]
    fn a_demangled_call_with_a_spelled_list_types_the_callee() {
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  Widget::Render(int,char *)(param_1, param_2);\n",
        );
        let records = from_body(&func);
        assert_eq!(
            params(&records),
            vec![(0, "int".into()), (1, "char *".into())]
        );
        let InferredType::Param(record) = &records[0] else {
            unreachable!("the call emits parameter records");
        };
        assert_eq!(record.function, "Widget::Render(int,char *)");
        assert_eq!(record.method, InferenceMethod::Mangling);
        assert_eq!(record.confidence, Confidence::new(MANGLING_CONFIDENCE));
        assert_eq!(
            record.evidence,
            "Widget::Render(int,char *)(param_1, param_2);"
        );
    }

    #[test]
    fn an_extra_call_argument_is_the_member_this() {
        // The decompiler spells a thiscall member call with the object
        // as its first argument: one more argument than the spelled list
        // places the list at 1 and types position 0 as the class.
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  Widget::Render(int,char *)(param_1, param_2, uVar3);\n",
        );
        let records = from_body(&func);
        assert_eq!(
            params(&records),
            vec![
                (0, "Widget *".into()),
                (1, "int".into()),
                (2, "char *".into()),
            ]
        );
    }

    #[test]
    fn a_name_without_a_parameter_list_produces_nothing() {
        // An ordinary qualified call — one group, the arguments — carries
        // no spelled contract; the this-pointer detector reads what usage
        // shows of it.
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::paint(param_1);\n  UdpLibrary::UdpRefCount::addref(param_1);\n",
        );
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn a_name_and_site_that_disagree_place_nothing() {
        // Two spelled parameters but four arguments: the list cannot be
        // placed without guessing, so nothing is typed.
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::Render(int,char *)(param_1, param_2, uVar3, uVar4);\n",
        );
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn namespace_noise_is_not_a_member_contract() {
        // `std::` library members and `operator` spellings name no class
        // contract for a parameter, spelled list or not.
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  std::string::compare(char *,char *)(param_1, param_2);\n\
             \x20 Widget::operator()(int)(param_1);\n",
        );
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn a_mangled_standard_library_symbol_names_no_contract() {
        // The listing-side half of the noise guard: a mangled `std::`
        // member decodes cleanly but names library plumbing, not a
        // member contract of the analyzed program.
        assert!(from_listing("?compare@string@std@@QBEPBH@Z").is_empty());
    }

    #[test]
    fn qualified_names_inside_string_literals_are_not_calls() {
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_1800412a0(\"Widget::Render(int,char *)(param_1)\", uVar2);\n",
        );
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn an_unparseable_parameter_list_names_no_contract() {
        // A template argument, a reference, and a named parameter all
        // fall outside the plain-declaration subset.
        let func = function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::load(std::vector<int> *)(param_1);\n\
             \x20 Widget::link(Widget &other)(param_1);\n\
             \x20 Widget::set(int width)(param_1);\n",
        );
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn the_analyzed_function_s_own_demangled_name_types_its_parameters() {
        // the decompiler carries the demangled name with the spelled list; the
        // decompiled signature places it — one more body parameter than
        // the name lists means the member's implicit this sits first.
        let func = DecompiledFunction {
            name: "Widget::Render(int,char *)".into(),
            signature: "void __thiscall Widget::Render(Widget *this,int param_1,char *param_2)"
                .into(),
            body: "\nvoid __thiscall Widget::Render(Widget *this,int param_1,char *param_2)\n\n{\n  return;\n}\n"
                .into(),
        };
        let records = from_body(&func);
        assert_eq!(
            params(&records),
            vec![(1, "int".into()), (2, "char *".into())]
        );
        let InferredType::Param(record) = &records[0] else {
            unreachable!("the name emits parameter records");
        };
        assert_eq!(record.function, "Widget::Render(int,char *)");
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.evidence, func.signature.trim());
    }

    #[test]
    fn an_own_name_the_signature_cannot_place_types_nothing() {
        // The name lists two parameters, the body declares three that
        // are not one-more-than... they are one more, so that places;
        // this body declares four, which places neither way.
        let func = DecompiledFunction {
            name: "Widget::Render(int,char *)".into(),
            signature: "void __thiscall Widget::Render(Widget *this,int param_1,char *param_2,undefined8 param_3)".into(),
            body: "\nvoid __thiscall Widget::Render(Widget *this,int param_1,char *param_2,undefined8 param_3)\n\n{\n  return;\n}\n".into(),
        };
        assert!(from_body(&func).is_empty());
    }

    #[test]
    fn a_mangled_own_name_is_the_listing_pass_reading_not_a_second_one() {
        // The engine reads the listing name once through
        // `detect_from_listing`; the body pass must not duplicate it.
        let func = function(
            "?paint@Widget@@QAEXXZ",
            "undefined ?paint@Widget@@QAEXXZ(undefined8 param_1)",
            "  return;\n",
        );
        assert!(from_body(&func).is_empty());
    }
}
