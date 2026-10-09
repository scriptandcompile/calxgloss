//! C++ this-pointer detection.
//!
//! [`ThisPointerDetector`] parses decompiled functions for `vtable[index]`
//! call patterns and first-parameter usage to recognize member functions,
//! extracts the class name from vtable function names, filters namespace
//! false positives (`std::`, `operator::`), and detects IUnknown-derived
//! COM interfaces. Each reading is emitted as an [`InferredParamType`]
//! record whose method is one of the this-pointer variants —
//! [`VtableCall`], [`FirstParamUsage`], or [`ComInterface`] — scoped to the
//! class the body reads the parameter as.
//!
//! [`InferredParamType`]: crate::types::InferredParamType
//! [`VtableCall`]: crate::types::InferenceMethod::VtableCall
//! [`FirstParamUsage`]: crate::types::InferenceMethod::FirstParamUsage
//! [`ComInterface`]: crate::types::InferenceMethod::ComInterface

use crate::types::{InferenceMethod, InferenceScope, InferredParamType};
use calxgloss_ghidra::DecompiledFunction;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use calxgloss_types::{closing_paren, is_ident_byte, line_at, skip_string, skip_ws};

// ============================================================
// Vtable call patterns
// ============================================================

/// The type text for a `this` pointer whose class the pattern cannot name:
/// a vtable call proves the parameter points to an object with a table of
/// functions, not which class owns that table. Readings that recover the
/// class name narrow this further.
const UNNAMED_CLASS: &str = "void *";

/// Confidence of a virtual call written as one expression: the callee
/// loads the table pointer out of the parameter and a slot out of the
/// table, and the call passes the parameter as its first argument.
const INLINE_CONFIDENCE: u8 = 85;

/// Confidence of a virtual call through a hoisted table base — the body
/// loads the parameter's table pointer into a local and dispatches slots
/// off it — one dereference further from the object than an inline call.
const HOISTED_CONFIDENCE: u8 = 75;

/// Confidence of a vtable call whose class the program also names: the
/// dispatch proves the parameter points at an object with a table of
/// functions, and a member call written as `Class::method(param, ...)` —
/// or the analyzed function's own demangled name — says which class owns
/// that table.
const NAMED_CLASS_CONFIDENCE: u8 = 90;

/// Confidence of a member-function name reading on its own: the body
/// passes the parameter as `Class::method`'s first argument, which fits a
/// `this` pointer but also a static call taking the object as its first
/// argument, so it carries no dispatch proof beside the name.
const MEMBER_CALL_CONFIDENCE: u8 = 80;

/// The type text for a parameter whose dispatches land on the COM
/// interface prefix: every `IUnknown`-derived interface puts
/// QueryInterface, AddRef, and Release at the first three vtable slots,
/// so a body dispatching two of the three through the parameter holds an
/// interface pointer.
const IUNKNOWN_INTERFACE: &str = "IUnknown *";

/// Confidence of an interface-pointer reading from the `IUnknown` slot
/// prefix: dispatches at the trio's exact slots are stronger evidence
/// than one anonymous virtual call, but the interface itself stays
/// unnamed — a program name for the class still refines further.
const COM_CONFIDENCE: u8 = 88;

/// The vtable slots the `IUnknown` prefix occupies: QueryInterface at 0,
/// AddRef at 1, Release at 2. Two of the three spell a COM interface;
/// one alone is an ordinary virtual call that could belong to any class.
const IUNKNOWN_SLOTS: usize = 3;

/// Pointer size used to turn a table byte offset into a slot index —
/// the x64 programs this pipeline analyzes.
const POINTER_SIZE: u64 = 8;

/// A Ghidra type cast inside an expression: `(code **)`, `(undefined8 *)`,
/// `(longlong)`. Stripping casts from a callee expression leaves the bare
/// dereference chain the call is built from.
fn type_cast() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\*+|undefined[0-9]?|ushort|uint|ulong|ulonglong|longlong|short|uchar|char|byte|word|dword|qword|void|code|size_t|wchar_t|bool)\s*\)",
        )
        .expect("static pattern")
    })
}

/// An assignment that hoists a vtable base (or a slot straight out of it)
/// into a local: `pcVar2 = *(code **)*param_1`. The first capture is the
/// local, the second the object the table was loaded from.
fn vtable_base_load() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"([A-Za-z_][A-Za-z0-9_]*) = \*+\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\*+\s*\)\s*\*?([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("static pattern")
    })
}

/// One indirect call found in a body: the callee expression, the first
/// argument, the byte offset of the call, and the vtable slot it
/// dispatches through.
struct IndirectCall<'a> {
    callee: &'a str,
    first_arg: &'a str,
    offset: usize,
    slot: usize,
}

/// Every indirect call `(*callee)(args)` or `(*callee)[slot](args)` in the
/// body, scanned outside string literals so a stray `(` in a format string
/// cannot unbalance the paren matching.
fn indirect_calls(body: &str) -> Vec<IndirectCall<'_>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' if bytes[i + 1] == b'*' => {
                if let Some(close) = closing_paren(body, i) {
                    let callee = body[i + 1..close].trim();
                    let (index, open) = slot_and_call_paren(body, close + 1);
                    if let Some(open) = open {
                        let first_arg = first_argument(body, open);
                        if is_identifier(first_arg) {
                            calls.push(IndirectCall {
                                callee,
                                first_arg,
                                offset: i,
                                slot: index.unwrap_or_else(|| inline_slot(callee)),
                            });
                        }
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    calls
}

/// The variable a callee expression double-dereferences, if it does:
/// `**(code **)*param_1` and `*(code *)((longlong)*param_1 + 0x18)` both
/// read the table pointer out of `param_1` and then index the table, so
/// the stripped expression carries at least two dereference stars before
/// the first identifier. A single star is a plain pointer load, and an
/// identifier before any star is a dispatch table or a hoisted local, not
/// a read through an object's own vptr.
fn double_deref_var(callee: &str) -> Option<String> {
    let stripped = type_cast().replace_all(callee, "");
    let bytes = stripped.as_bytes();
    let mut stars = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'*' => {
                stars += 1;
                i += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                return (stars >= 2).then(|| stripped[start..i].to_string());
            }
            _ => i += 1,
        }
    }
    None
}

/// The vtable slot an inline dispatch reads: a bare double-deref is slot
/// 0, `+ 0x18` added to the loaded table pointer is slot 3, and an
/// offset added to the object itself — `**(param_1 + 0x10)`, a secondary
/// table behind a field — is slot 0 of that table.
fn inline_slot(callee: &str) -> usize {
    let stripped = type_cast().replace_all(callee, "");
    let bytes = stripped.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'+' {
            continue;
        }
        let start = skip_ws(bytes, i + 1);
        let end = number_end(bytes, start);
        if let Some(offset) = parse_offset(&stripped[start..end]) {
            if adds_to_object(&stripped, i) {
                return 0;
            }
            return (offset / POINTER_SIZE) as usize;
        }
    }
    0
}

/// Whether the `+` at `plus` adds to the object rather than to a loaded
/// table pointer: the group holding the `+` opens right behind two or
/// more dereference stars (`**(param_1 + 0x10)`), which means the table
/// pointer is read out of the offset object. A `+` with no enclosing
/// group adds to the table pointer the expression has already loaded.
fn adds_to_object(expr: &str, plus: usize) -> bool {
    let bytes = expr.as_bytes();
    let mut depth = 0usize;
    let mut i = plus;
    let open = loop {
        if i == 0 {
            return false;
        }
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' if depth == 0 => break i,
            b'(' => depth -= 1,
            _ => {}
        }
    };
    let mut stars = 0usize;
    let mut k = open;
    while k > 0 && bytes[k - 1] == b'*' {
        k -= 1;
        stars += 1;
    }
    stars >= 2
}

/// The index just past the `0x`-prefixed hex or decimal number starting
/// at `start` — `start` itself when no number is spelled there.
fn number_end(bytes: &[u8], start: usize) -> usize {
    let hex = bytes[start..].starts_with(b"0x") || bytes[start..].starts_with(b"0X");
    let mut i = if hex { start + 2 } else { start };
    while i < bytes.len()
        && (hex && bytes[i].is_ascii_hexdigit() || !hex && bytes[i].is_ascii_digit())
    {
        i += 1;
    }
    i
}

/// A byte offset or slot index as the decompiler spells it: `0x18` or
/// `24`.
fn parse_offset(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// Objects whose hoisted vtable base is dispatched through: for every
/// `base = *(code **)*object` load, the body must also call through `base`
/// with `object` as the first argument. The load's line is the evidence
/// that the object carries a vtable; each dispatch carries its slot and
/// its own line beside it.
fn hoisted_dispatches(body: &str) -> Vec<(String, usize, usize, usize)> {
    let mut dispatches = Vec::new();
    for caps in vtable_base_load().captures_iter(body) {
        let (Some(load), Some(base), Some(object)) = (caps.get(0), caps.get(1), caps.get(2)) else {
            continue;
        };
        for (arg, slot, offset) in calls_through(body, base.as_str()) {
            if arg == object.as_str() {
                dispatches.push((object.as_str().to_string(), load.start(), slot, offset));
            }
        }
    }
    dispatches
}

/// The first arguments, vtable slots, and byte offsets of every call made
/// through `base`: `base[3](x)`, `(base[3])(x)`, `(*base)(x)`,
/// `(base + 0x18)(x)`. A `[N]` index counts table elements; a `+` offset
/// counts bytes.
fn calls_through<'a>(body: &'a str, base: &str) -> Vec<(&'a str, usize, usize)> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut from = 0;
    while let Some(rel) = body[from..].find(base) {
        let start = from + rel;
        let end = start + base.len();
        from = end;
        let whole_word = (start == 0 || !is_ident_byte(bytes[start - 1]))
            && (end == bytes.len() || !is_ident_byte(bytes[end]));
        if !whole_word {
            continue;
        }
        let mut i = skip_ws(bytes, end);
        let mut slot = 0;
        if bytes.get(i) == Some(&b'[') {
            match body[i..].find(']') {
                Some(rel) => {
                    slot = parse_offset(&body[i + 1..i + rel]).unwrap_or(0) as usize;
                    i = skip_ws(bytes, i + rel + 1);
                }
                None => continue,
            }
        } else if bytes.get(i) == Some(&b'+') {
            let num_start = skip_ws(bytes, i + 1);
            let num_end = number_end(bytes, num_start);
            slot = parse_offset(&body[num_start..num_end])
                .map_or(0, |offset| (offset / POINTER_SIZE) as usize);
            while i < bytes.len() && !matches!(bytes[i], b'(' | b')' | b'"') {
                i += 1;
            }
            i = skip_ws(bytes, i);
        }
        if bytes.get(i) == Some(&b')') {
            i = skip_ws(bytes, i + 1);
        }
        if bytes.get(i) == Some(&b'(') {
            let first_arg = first_argument(body, i);
            if is_identifier(first_arg) {
                args.push((first_arg, slot, start));
            }
        }
    }
    args
}
/// The `[slot]` index and the `(` opening the argument list that follows
/// a closed callee.
fn slot_and_call_paren(body: &str, from: usize) -> (Option<usize>, Option<usize>) {
    let bytes = body.as_bytes();
    let mut i = skip_ws(bytes, from);
    let mut slot = None;
    if bytes.get(i) == Some(&b'[') {
        match body[i..].find(']') {
            Some(rel) => {
                slot = parse_offset(&body[i + 1..i + rel]).map(|index| index as usize);
                i = skip_ws(bytes, i + rel + 1);
            }
            None => return (None, None),
        }
    }
    let open = (bytes.get(i) == Some(&b'(')).then_some(i);
    (slot, open)
}

/// The text of the first argument of the call whose `(` sits at `open`.
fn first_argument(body: &str, open: usize) -> &str {
    let bytes = body.as_bytes();
    let mut depth = 1usize;
    let mut i = open + 1;
    let start = i;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                i += 1;
            }
            b',' if depth == 1 => break,
            _ => i += 1,
        }
    }
    body[start..i].trim()
}
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => chars.all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}

// ============================================================
// Class names from member function names
// ============================================================

/// A direct call to a qualified name — `Widget::paint(param_1, uVar2)` —
/// found in a body: the callee name, the raw first argument, and the byte
/// offset of the call.
struct QualifiedCall<'a> {
    callee: &'a str,
    first_arg: &'a str,
    offset: usize,
}

/// Every direct call `a::b::method(args)` in the body whose callee is a
/// chain of segments joined by `::`, scanned outside string literals. A
/// chain not immediately followed by `(` is a qualified type or variable
/// reference, not a call, and a single-segment name is an ordinary call
/// the vtable patterns already weigh.
fn qualified_calls(body: &str) -> Vec<QualifiedCall<'_>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
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
                        calls.push(QualifiedCall {
                            callee: &body[i..end],
                            first_arg: first_argument(body, open),
                            offset: i,
                        });
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
    calls
}

/// The end of the callee span and the position of the argument-list `(`
/// for a qualified call whose name starts at `start`. A destructor segment
/// may carry a leading `~` (`Widget::~Widget`).
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

/// Qualified-name segments that mark library or operator plumbing rather
/// than a class of the analyzed program: `std` roots the C++ standard
/// library (`std::string::compare`) and `operator` spells an operator
/// function (`operator::new`, `Widget::operator()`). A parameter passed to
/// such a call is not a `this` pointer for a program class, so a chain
/// carrying either segment names no class. The match is on whole segments,
/// so a program namespace that merely holds one of these words (`MyStd`)
/// still names its class.
const NAMESPACE_NOISE: [&str; 2] = ["std", "operator"];

/// The class a qualified callee name names: `Widget::paint` → `Widget`,
/// `UdpLibrary::UdpRefCount::addref` → `UdpLibrary::UdpRefCount`. The last
/// segment is the method — a destructor's leading `~` ignored — and a name
/// names no class when any segment is not a plain identifier (a template
/// instantiation, a global-scope `::operator new`) or is namespace noise
/// ([`NAMESPACE_NOISE`]: a `std::` library call, an `operator` spelling).
fn class_name(callee: &str) -> Option<String> {
    let mut segments = callee.split("::").collect::<Vec<_>>();
    if segments.len() < 2 || segments.iter().any(|s| NAMESPACE_NOISE.contains(s)) {
        return None;
    }
    let method = segments.pop()?;
    let method = method.strip_prefix('~').unwrap_or(method);
    let named = is_identifier(method) && segments.iter().all(|s| is_identifier(s));
    named.then(|| segments.join("::"))
}

/// The class the analyzed function's own name names, when Ghidra carries a
/// demangled member name: `Widget::paint(void)` says the function is a
/// member of `Widget`, whose first parameter is the class's `this`
/// pointer.
fn self_class_name(name: &str) -> Option<String> {
    class_name(name.split('(').next()?)
}

/// A call argument with Ghidra casts stripped: the decompiler writes
/// `Widget::paint((Widget *)param_1, ...)` when the argument's applied
/// type differs from the callee's parameter, and the object behind the
/// cast is what the reading is about.
fn strip_casts(arg: &str) -> String {
    type_cast().replace_all(arg, "").trim().to_string()
}

// ============================================================
// Detector
// ============================================================

/// C++ this-pointer detection over decompiled functions.
///
/// The detector is stateless: every reading comes from the decompiled
/// function it is handed, so one detector serves an entire scan and can be
/// shared across concurrent per-function passes. It holds no Ghidra client
/// of its own — the [`DecompiledFunction`] text is fetched once per
/// function and read by every detector — and it never writes back to the
/// program, only reporting what the body's usage implies.
///
/// [`DecompiledFunction`]: calxgloss_ghidra::DecompiledFunction
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThisPointerDetector;

impl ThisPointerDetector {
    /// A detector with the full standard detection set: `vtable[index]`
    /// call patterns, first-parameter usage, and COM interface prefixes.
    pub fn new() -> Self {
        Self
    }

    /// Read `this` pointers from the `vtable[index]` call patterns in a
    /// decompiled body.
    ///
    /// A parameter is read as a `this` pointer when the body calls through
    /// the table its first word points at and passes the parameter as the
    /// call's first argument. Two spellings carry that shape: the call
    /// double-dereferences the parameter inline — `(**(code **)*param_1)
    /// (param_1)`, `(*(code *)(**param_1 + 0x18))(param_1)`,
    /// `(*(code *)(**param_1))[3](param_1)` — or the body hoists the table
    /// base into a local and dispatches through it — `pcVar2 =
    /// *(code **)*param_1;` then `pcVar2[3](param_1);`. A call through a
    /// table that does not pass the object it loaded from as its first
    /// argument is a delegate, not a member call, and yields nothing.
    ///
    /// The dispatch pattern proves the parameter points to an object with
    /// a vtable, not which class owns the table, so a bare reading narrows
    /// the parameter to an unnamed class pointer ([`UNNAMED_CLASS`]) at
    /// class scope — the inference belongs to the class, not just this
    /// function. When the program names the class, the record narrows to
    /// `Class *` instead: the analyzed function carries a demangled member
    /// name (`Widget::paint(void)`), or the body calls a qualified member
    /// function with the parameter as its first argument
    /// (`Widget::paint(param_1, ...)`). Qualified calls rooted in the `std`
    /// namespace or spelled as `operator` functions name no class and
    /// refine nothing. When the dispatches land on the first three slots
    /// of the table — QueryInterface at 0, AddRef at 1, Release at 2 — the
    /// object is an `IUnknown`-derived COM interface and the reading
    /// narrows to `IUnknown *` through [`InferenceMethod::ComInterface`];
    /// two of the three slots spell the prefix, one alone is an ordinary
    /// virtual call. At most one record is emitted per parameter, carrying
    /// the strongest evidence the body offers.
    pub fn detect_this_pointer(&self, func: &DecompiledFunction) -> Vec<InferredParamType> {
        let params = func.parameter_names();
        if params.is_empty() {
            return Vec::new();
        }

        let mut unnamed: Vec<(usize, u8, String)> = Vec::new();
        let mut slots: Vec<(usize, usize, String)> = Vec::new();
        for call in indirect_calls(&func.body) {
            if let Some(object) = double_deref_var(call.callee)
                && object == call.first_arg
                && let Some(index) = params.iter().position(|p| p == &object)
            {
                let line = line_at(&func.body, call.offset);
                unnamed.push((index, INLINE_CONFIDENCE, line.clone()));
                slots.push((index, call.slot, line));
            }
        }
        for (object, load, slot, call) in hoisted_dispatches(&func.body) {
            if let Some(index) = params.iter().position(|p| p == &object) {
                unnamed.push((index, HOISTED_CONFIDENCE, line_at(&func.body, load)));
                slots.push((index, slot, line_at(&func.body, call)));
            }
        }

        // The COM reading: a parameter dispatched at two or three of the
        // IUnknown slots is an interface pointer. The evidence line is
        // the deepest trio dispatch — Release, when the body calls it.
        let mut com: Vec<(usize, String)> = Vec::new();
        for index in 0..params.len() {
            let mut trio: BTreeMap<usize, String> = BTreeMap::new();
            for (at, slot, line) in &slots {
                if *at == index && *slot < IUNKNOWN_SLOTS {
                    trio.entry(*slot).or_insert_with(|| line.clone());
                }
            }
            if trio.len() >= 2
                && let Some((_, line)) = trio.iter().next_back()
            {
                com.push((index, line.clone()));
            }
        }

        // Class names, in source priority order: the analyzed function's
        // own demangled name speaks for its first parameter, and a member
        // call in the body speaks for whatever it passes as `this`.
        let mut named: Vec<(usize, String, String)> = Vec::new();
        if let Some(class) = self_class_name(&func.name) {
            named.push((0, class, func.signature.trim().to_string()));
        }
        for call in qualified_calls(&func.body) {
            let object = strip_casts(call.first_arg);
            if let Some(class) = class_name(call.callee)
                && let Some(index) = params.iter().position(|p| *p == object)
            {
                named.push((index, class, line_at(&func.body, call.offset)));
            }
        }

        params
            .iter()
            .enumerate()
            .filter_map(|(index, name)| {
                let named = named.iter().find(|(at, _, _)| *at == index);
                let com = com.iter().find(|(at, _)| *at == index);
                let unnamed = unnamed
                    .iter()
                    .filter(|(at, _, _)| *at == index)
                    .max_by_key(|(_, score, _)| *score);
                let (inferred_type, method, confidence, evidence) = match (named, com, unnamed) {
                    (Some((_, class, evidence)), _, Some(_)) => (
                        format!("{class} *"),
                        InferenceMethod::VtableCall,
                        NAMED_CLASS_CONFIDENCE,
                        evidence.clone(),
                    ),
                    (Some((_, class, evidence)), _, None) => (
                        format!("{class} *"),
                        InferenceMethod::FirstParamUsage,
                        MEMBER_CALL_CONFIDENCE,
                        evidence.clone(),
                    ),
                    (None, Some((_, evidence)), _) => (
                        IUNKNOWN_INTERFACE.to_string(),
                        InferenceMethod::ComInterface,
                        COM_CONFIDENCE,
                        evidence.clone(),
                    ),
                    (None, None, Some((_, confidence, evidence))) => (
                        UNNAMED_CLASS.to_string(),
                        InferenceMethod::VtableCall,
                        *confidence,
                        evidence.clone(),
                    ),
                    (None, None, None) => return None,
                };
                Some(InferredParamType {
                    function: func.name.clone(),
                    param_index: index,
                    param_name: Some(name.clone()),
                    inferred_type,
                    method,
                    scope: InferenceScope::Class,
                    confidence: confidence.into(),
                    evidence,
                })
            })
            .collect()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: signature.into(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    fn one_reading(func: &DecompiledFunction) -> InferredParamType {
        let records = ThisPointerDetector::new().detect_this_pointer(func);
        assert_eq!(records.len(), 1, "expected exactly one reading");
        records.into_iter().next().unwrap()
    }

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = ThisPointerDetector::new();
        assert_eq!(detector, ThisPointerDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven concurrently over a program's functions,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ThisPointerDetector>();
    }

    #[test]
    fn a_virtual_call_through_the_first_parameter_is_detected() {
        let func = function(
            "undefined __thiscall FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        // The pattern proves an object with a vtable, not the class name.
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
        assert_eq!(record.scope, InferenceScope::Class);
        assert_eq!(record.confidence, INLINE_CONFIDENCE);
        assert_eq!(record.evidence, "(**(code **)*param_1)(param_1);");
        assert!(record.is_this_pointer());
    }

    #[test]
    fn an_indexed_slot_call_is_detected() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(**param_1))[3](param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.evidence, "(*(code *)(**param_1))[3](param_1);");
    }

    #[test]
    fn a_byte_offset_into_the_table_is_detected() {
        // The decompiler spells a slot either as an indexed table base or
        // as raw arithmetic on the table pointer.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(**param_1 + 0x18))(param_1);\n\
             \x20 (*(code *)((longlong)*param_1 + 0x20))(param_1);\n",
        );
        let records = ThisPointerDetector::new().detect_this_pointer(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
    }

    #[test]
    fn a_secondary_vtable_behind_a_field_offset_is_detected() {
        // Multiple inheritance puts a second table at a field offset; the
        // object still carries a vtable, so the reading stands.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)(param_1 + 0x10))(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.confidence, INLINE_CONFIDENCE);
    }

    #[test]
    fn a_hoisted_table_base_dispatch_is_detected() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  code *pcVar2;\n\
             \n\
             \x20 pcVar2 = *(code **)*param_1;\n\
             \x20 pcVar2[3](param_1);\n\
             \x20 pcVar2[7](param_1, 2);\n",
        );
        let record = one_reading(&func);
        // The load line is the evidence: it is what shows the parameter
        // carries a table pointer.
        assert_eq!(record.evidence, "pcVar2 = *(code **)*param_1;");
        assert_eq!(record.confidence, HOISTED_CONFIDENCE);
    }

    #[test]
    fn the_reading_follows_the_parameter_carrying_the_object() {
        // An interface pointer arriving as a later parameter gets its own
        // reading at its own position.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1,undefined8 param_2)",
            "  (**(code **)*param_2)(param_2, param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.param_index, 1);
        assert_eq!(record.param_name.as_deref(), Some("param_2"));
    }

    #[test]
    fn a_call_that_passes_something_else_as_the_object_is_not_a_reading() {
        // A function pointer loaded from the object but invoked on another
        // value is a delegate, not a member call through a vtable.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(uVar2);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn a_double_dereference_of_a_local_is_not_a_parameter_reading() {
        // The object has to be a parameter; a local's vtable says nothing
        // about the signature.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*puVar4)(puVar4);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn direct_calls_and_single_dereferences_are_not_vtable_calls() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_18001234(param_1);\n\
             \x20 *param_1 = 0;\n\
             \x20 *(undefined4 *)(param_1 + 4) = uVar2;\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn a_dispatch_table_call_is_not_a_vtable_call() {
        // `table + index * 4` indexes a standalone jump table, not a vptr
        // read out of the parameter.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(DAT_180130000 + uVar4 * 4))(param_1);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn a_function_without_parameters_yields_no_readings() {
        let func = function("undefined FUN_18003ab00(void)", "  return;\n");
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn the_strongest_evidence_wins_for_one_parameter() {
        // A body that both hoists the table base and calls inline yields a
        // single record, backed by the direct call.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  pcVar2 = *(code **)*param_1;\n\
             \x20 pcVar2[3](param_1);\n\
             \x20 (**(code **)*param_1)(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.confidence, INLINE_CONFIDENCE);
        assert_eq!(record.evidence, "(**(code **)*param_1)(param_1);");
    }

    #[test]
    fn string_literals_do_not_disturb_the_scan() {
        // A format string holding a stray `(` must not unbalance the
        // paren matching around a real virtual call.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_1800412a0(\"paint (\", param_1);\n\
             \x20 (**(code **)*param_1)(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.evidence, "(**(code **)*param_1)(param_1);");
    }

    #[test]
    fn a_named_member_call_beside_a_vtable_call_names_the_class() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1);\n\
             \x20 Widget::paint(param_1, uVar2);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "Widget *");
        // The dispatch still carries the reading; the name only refines
        // which class the table belongs to.
        assert_eq!(record.method, InferenceMethod::VtableCall);
        assert_eq!(record.confidence, NAMED_CLASS_CONFIDENCE);
        assert_eq!(record.evidence, "Widget::paint(param_1, uVar2);");
    }

    #[test]
    fn a_member_call_without_a_vtable_dispatch_is_a_usage_reading() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::paint(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "Widget *");
        assert_eq!(record.method, InferenceMethod::FirstParamUsage);
        assert_eq!(record.confidence, MEMBER_CALL_CONFIDENCE);
        assert!(record.is_this_pointer());
    }

    #[test]
    fn a_cast_argument_still_names_the_object() {
        // The decompiler casts the argument when its applied type differs
        // from the callee's parameter; the object behind the cast is what
        // the reading is about.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::paint((Widget *)param_1, uVar2);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.param_index, 0);
        assert_eq!(record.inferred_type, "Widget *");
    }

    #[test]
    fn a_nested_namespace_qualifier_keeps_the_class_chain() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  UdpLibrary::UdpRefCount::addref(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "UdpLibrary::UdpRefCount *");
    }

    #[test]
    fn a_standard_library_call_is_not_a_member_reading() {
        // `std::` roots the C++ standard library: a parameter passed to a
        // library member is not a this pointer for a class of the program.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  std::string::compare(param_1, param_2);\n\
             \x20 std::string::c_str(param_1);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn an_operator_spelling_is_not_a_member_reading() {
        // `operator::new` and a call to `operator()` are operator
        // plumbing, not member calls naming a class for the parameter.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  operator::new(0x10);\n\
             \x20 Widget::operator()(param_1);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn a_namespace_holding_a_noise_word_as_a_substring_still_names_the_class() {
        // The guard matches whole segments: `MyStd` is a program namespace
        // like any other, and its member call names the class chain.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  MyStd::string::paint(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "MyStd::string *");
    }

    #[test]
    fn a_destructor_call_names_the_class() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::~Widget(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "Widget *");
    }

    #[test]
    fn the_analyzed_function_s_own_member_name_names_its_class() {
        // Ghidra demangles `?paint@Widget@@QAEXXZ` to `Widget::paint(void)`;
        // a member function's first parameter is the class's this pointer.
        let func = DecompiledFunction {
            name: "Widget::paint(void)".into(),
            signature: "void __thiscall Widget::paint(Widget *this)".into(),
            body: "\nvoid __thiscall Widget::paint(Widget *this)\n\n{\n  (**(code **)*this)(this);\n}\n"
                .into(),
        };
        let record = one_reading(&func);
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("this"));
        assert_eq!(record.inferred_type, "Widget *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
        assert_eq!(record.confidence, NAMED_CLASS_CONFIDENCE);
    }

    #[test]
    fn a_qualified_call_on_a_local_or_a_malformed_name_is_not_a_reading() {
        // A static-style call on a local, a global-scope `::operator new`,
        // and a template instantiation all name no class for a parameter.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  Widget::create(uVar3);\n\
             \x20 ::operator new(0x10);\n\
             \x20 std::vector<int>::push_back(param_1);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn qualified_names_inside_string_literals_are_not_calls() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_1800412a0(\"Widget::paint(param_1)\", uVar2);\n",
        );
        assert!(
            ThisPointerDetector::new()
                .detect_this_pointer(&func)
                .is_empty()
        );
    }

    #[test]
    fn the_iunknown_slot_trio_marks_an_interface_pointer() {
        // Every IUnknown-derived interface opens with QueryInterface at
        // slot 0, AddRef at 1, Release at 2: a body dispatching all
        // three through the parameter holds a COM interface pointer.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1, &DAT_180130000, &local_38);\n\
             \x20 (*(code *)(**param_1 + 0x8))(param_1);\n\
             \x20 (*(code *)(**param_1 + 0x10))(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "IUnknown *");
        assert_eq!(record.method, InferenceMethod::ComInterface);
        assert_eq!(record.scope, InferenceScope::Class);
        assert_eq!(record.confidence, COM_CONFIDENCE);
        assert_eq!(record.evidence, "(*(code *)(**param_1 + 0x10))(param_1);");
        assert!(record.is_this_pointer());
    }

    #[test]
    fn addref_and_release_alone_spell_the_interface_prefix() {
        // QueryInterface is the one slot a plain class also dispatches
        // as its first virtual; the refcount pair alone is enough.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(**param_1 + 0x8))(param_1);\n\
             \x20 (*(code *)(**param_1 + 0x10))(param_1, 1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.method, InferenceMethod::ComInterface);
        assert_eq!(
            record.evidence,
            "(*(code *)(**param_1 + 0x10))(param_1, 1);"
        );
    }

    #[test]
    fn one_iunknown_slot_is_an_ordinary_virtual_call() {
        // A single slot-0 dispatch could belong to any class; the trio
        // is what spells COM.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
    }

    #[test]
    fn com_slots_are_recognized_through_a_hoisted_table_base() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  code *pcVar2;\n\
             \n\
             \x20 pcVar2 = *(code **)*param_1;\n\
             \x20 pcVar2[1](param_1);\n\
             \x20 pcVar2[2](param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.method, InferenceMethod::ComInterface);
        assert_eq!(record.evidence, "pcVar2[2](param_1);");
    }

    #[test]
    fn indexed_slot_calls_spell_the_trio() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(**param_1))[1](param_1);\n\
             \x20 (*(code *)(**param_1))[2](param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.method, InferenceMethod::ComInterface);
        assert_eq!(record.inferred_type, "IUnknown *");
    }

    #[test]
    fn dispatches_past_the_iunknown_prefix_are_not_com_slots() {
        // Slots 3 and up are the interface's own methods: ordinary
        // virtual calls, not the IUnknown prefix.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (*(code *)(**param_1 + 0x18))(param_1);\n\
             \x20 (*(code *)(**param_1 + 0x20))(param_1);\n\
             \x20 (*(code *)(**param_1 + 0x28))(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
    }

    #[test]
    fn a_secondary_table_offset_is_slot_zero_of_its_own_table() {
        // `**(param_1 + 0x10)` adds the offset to the object, not to a
        // loaded table pointer: it reads a secondary vtable's slot 0,
        // not Release.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1);\n\
             \x20 (**(code **)(param_1 + 0x10))(param_1);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
    }

    #[test]
    fn a_named_class_refines_past_the_com_reading() {
        // A program name for the class says more than the generic
        // interface prefix, even when the body also dispatches the trio.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  (**(code **)*param_1)(param_1, &DAT_180130000, &local_38);\n\
             \x20 (*(code *)(**param_1 + 0x8))(param_1);\n\
             \x20 (*(code *)(**param_1 + 0x10))(param_1);\n\
             \x20 ISprite::draw(param_1, uVar2);\n",
        );
        let record = one_reading(&func);
        assert_eq!(record.inferred_type, "ISprite *");
        assert_eq!(record.method, InferenceMethod::VtableCall);
        assert_eq!(record.confidence, NAMED_CLASS_CONFIDENCE);
    }
}
