//! Known type propagation.
//!
//! [`KnownTypePropagationEngine`] extracts calls from decompiled text and
//! propagates parameter types through a signature database of well-known
//! library functions — `malloc`, `free`, `realloc`, `strlen`, `strcmp`,
//! `strcpy`, `memcpy`, `memset`, `CloseHandle`, `CreateFileW` — matching
//! names with A/W-suffix support and applying per-signature confidence
//! scores.

use crate::reading::Reading;
use crate::types::{InferenceMethod, InferenceScope, InferredParamType};
use calxgloss_ghidra::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at, strip_casts,
};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords — `if (x)` — not calls.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Signature database
// ============================================================

/// Confidence of a reading propagated from a C standard-library routine:
/// the contract behind the name is textbook, but the name is the whole
/// evidence — a project-local helper could carry the same spelling — so
/// the reading sits at the string-call confidence the size detector
/// already gives these same call sites.
const LIBC_CONFIDENCE: u8 = 70;

/// Confidence of a reading propagated from a Win32 API routine: the
/// names are distinctive — `CloseHandle` and `CreateFileW` are not
/// spellings a project-local helper would take — so the contract reaches
/// a little further than the C library's.
const WIN32_CONFIDENCE: u8 = 75;

/// The type text for an argument a contract reads as a byte buffer: the
/// call proves the argument points into memory, not at what — a heap
/// block, a handle, and a raw buffer all read the same way.
const BYTE_BUFFER: &str = "void *";

/// The type text for an argument a contract reads as a NUL-terminated
/// character string.
const CHAR_STRING: &str = "char *";

/// The type text for an argument a contract reads as a NUL-terminated
/// wide-character string — the `W` half of the Win32 A/W split, which is
/// what separates a `CreateFileW` name argument from its `A` twin's.
const WIDE_STRING: &str = "wchar_t *";

/// The type text for an argument a contract reads as a byte count: the
/// allocator and byte-routine sizes are unsigned counts of the platform
/// width, which the decompiler's default word cannot always hold.
const BYTE_COUNT: &str = "size_t";

/// The type text for the fill value `memset` copies into every byte: an
/// `int` by contract, not a pointer — the position that separates a
/// `memset` call from a `memcpy` one.
const FILL_VALUE: &str = "i32";

/// One argument position of a known routine and the type its contract
/// propagates to an argument sitting there. Positions start at 0, the
/// same convention the size detector's string table uses; a position the
/// contract does not read — `CreateFileW`'s sharing modes and flags — is
/// simply absent, and an argument sitting there gets no reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureArg {
    /// Argument position in the call, starting at 0.
    pub position: usize,
    /// The type an argument at this position is read as.
    pub inferred_type: &'static str,
}

/// A well-known library routine and what one of its call sites implies:
/// the callee name to match, the per-position contract readings, and the
/// confidence the signature carries wherever it matches. Names are
/// spelled exactly as decompiled text shows them; A/W-suffix tolerance
/// happens when a call is looked up, not in the entry itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownSignature {
    /// The callee name as decompiled text spells it, e.g. `CreateFileW`.
    pub name: &'static str,
    /// The contract's per-argument readings, in position order.
    pub args: &'static [SignatureArg],
    /// Confidence the signature carries at a matching call site, 0–100.
    pub confidence: u8,
}

/// The standard signature set: the allocator, string, byte-fill, and
/// handle routines whose parameter contracts propagate to the arguments
/// at their call sites. The string trio (`strlen`, `strcmp`, `strcpy`)
/// repeats the size detector's table on purpose — one call site is
/// evidence to both detectors, and conflict resolution keeps the
/// stronger reading — while the rest of the set reaches positions the
/// size detector's families never read: the count beside a `malloc`, the
/// buffers behind a `memcpy`, the handle behind a `CloseHandle`, the
/// wide name behind a `CreateFileW`.
pub const KNOWN_SIGNATURES: &[KnownSignature] = &[
    KnownSignature {
        name: "free",
        args: &[SignatureArg {
            position: 0,
            inferred_type: BYTE_BUFFER,
        }],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "malloc",
        args: &[SignatureArg {
            position: 0,
            inferred_type: BYTE_COUNT,
        }],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "realloc",
        args: &[
            SignatureArg {
                position: 0,
                inferred_type: BYTE_BUFFER,
            },
            SignatureArg {
                position: 1,
                inferred_type: BYTE_COUNT,
            },
        ],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "strlen",
        args: &[SignatureArg {
            position: 0,
            inferred_type: CHAR_STRING,
        }],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "strcmp",
        args: &[
            SignatureArg {
                position: 0,
                inferred_type: CHAR_STRING,
            },
            SignatureArg {
                position: 1,
                inferred_type: CHAR_STRING,
            },
        ],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "strcpy",
        args: &[
            SignatureArg {
                position: 0,
                inferred_type: CHAR_STRING,
            },
            SignatureArg {
                position: 1,
                inferred_type: CHAR_STRING,
            },
        ],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "memcpy",
        args: &[
            SignatureArg {
                position: 0,
                inferred_type: BYTE_BUFFER,
            },
            SignatureArg {
                position: 1,
                inferred_type: BYTE_BUFFER,
            },
            SignatureArg {
                position: 2,
                inferred_type: BYTE_COUNT,
            },
        ],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "memset",
        args: &[
            SignatureArg {
                position: 0,
                inferred_type: BYTE_BUFFER,
            },
            SignatureArg {
                position: 1,
                inferred_type: FILL_VALUE,
            },
            SignatureArg {
                position: 2,
                inferred_type: BYTE_COUNT,
            },
        ],
        confidence: LIBC_CONFIDENCE,
    },
    KnownSignature {
        name: "CloseHandle",
        args: &[SignatureArg {
            position: 0,
            inferred_type: BYTE_BUFFER,
        }],
        confidence: WIN32_CONFIDENCE,
    },
    KnownSignature {
        name: "CreateFileW",
        args: &[SignatureArg {
            position: 0,
            inferred_type: WIDE_STRING,
        }],
        confidence: WIN32_CONFIDENCE,
    },
];
/// The type words a Ghidra cast may spell, matching the decompiler's
/// vocabulary the this-pointer scan already strips.
fn is_type_word(word: &str) -> bool {
    matches!(
        word,
        "undefined"
            | "undefined1"
            | "undefined2"
            | "undefined3"
            | "undefined4"
            | "undefined5"
            | "undefined6"
            | "undefined7"
            | "undefined8"
            | "ushort"
            | "uint"
            | "ulong"
            | "ulonglong"
            | "longlong"
            | "short"
            | "uchar"
            | "char"
            | "byte"
            | "word"
            | "dword"
            | "qword"
            | "void"
            | "code"
            | "size_t"
            | "wchar_t"
            | "bool"
            | "int"
            | "float"
            | "double"
            | "long"
    )
}

// ============================================================
// Name matching
// ============================================================

/// The `A`/`W` family a suffixed name stands for: `CreateFileW` splits
/// into the base `CreateFile` and the tail letter `W`, and either
/// spelling of the tail names the same routine — the Win32 convention
/// where the bare base is a macro and the imports carry only suffixed
/// forms. A name without an `A`/`W` tail, or a tail standing alone,
/// names no family.
fn aw_family(name: &str) -> Option<(&str, char)> {
    let tail = name.chars().next_back()?;
    if !matches!(tail, 'A' | 'W') {
        return None;
    }
    let base = &name[..name.len() - 1];
    (!base.is_empty()).then_some((base, tail))
}

/// The signature a callee name resolves to: the entry whose name the
/// callee spells exactly, or failing that the entry sharing the callee's
/// `A`/`W` family — a `CreateFileA` call site resolves to the
/// `CreateFileW` entry, the two spellings being one contract over two
/// character sets, which the callee's own spelling settles when the
/// readings are taken. A bare base name resolves to nothing: the macro
/// form never reaches a PE import table, and the tail letter is the only
/// evidence of which character set the arguments carry. Everything else
/// names no family — `CreateFile2` and `CreateFileExW` are different
/// contracts, `myCreateFileW` is a longer name, and `CloseHandleA` or
/// `strlenA` find no twin because an entry without a tail opens no
/// family.
fn find_signature(callee: &str) -> Option<&'static KnownSignature> {
    KNOWN_SIGNATURES
        .iter()
        .find(|entry| entry.name == callee)
        .or_else(|| {
            let (base, _) = aw_family(callee)?;
            KNOWN_SIGNATURES.iter().find(|entry| {
                aw_family(entry.name).is_some_and(|(entry_base, _)| entry_base == base)
            })
        })
}

/// A callee resolved to a signature family: the database entry and the
/// spelling that resolved to it. The spelling travels with the match
/// because the character-set readings follow it — the `W` tail of
/// `CreateFileW` reads its name argument as `wchar_t *` where the `A`
/// tail of its twin reads the same position as `char *` — while every
/// other position's reading is the entry's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureMatch<'a> {
    /// The database entry the callee resolved to.
    pub signature: &'static KnownSignature,
    /// The callee name as the body spelled it, e.g. `CreateFileA`.
    pub callee: &'a str,
}

impl SignatureMatch<'_> {
    /// The entry's per-position readings with the character set settled
    /// against the callee's spelling: a string position reads as
    /// `wchar_t *` when the callee carries a `W` tail and `char *`
    /// otherwise, and every other reading — a buffer, a count, a fill
    /// value — is the entry's own. Positions the contract does not read
    /// stay absent and the order is unchanged.
    pub fn resolved_args(&self) -> Vec<SignatureArg> {
        self.signature
            .args
            .iter()
            .map(|arg| SignatureArg {
                position: arg.position,
                inferred_type: match arg.inferred_type {
                    CHAR_STRING | WIDE_STRING => {
                        if self.callee.ends_with('W') {
                            WIDE_STRING
                        } else {
                            CHAR_STRING
                        }
                    }
                    other => other,
                },
            })
            .collect()
    }
}

// ============================================================
// Engine
// ============================================================

/// One direct call extracted from a decompiled body: the callee name as
/// the body spells it, the text of each top-level argument, and the
/// source line holding the call.
///
/// The record is the raw shape of a call site — no name is matched
/// against the signature database and no argument is read here; those
/// happen when a call is looked up and its arguments are read against a
/// contract. The evidence line is carried because every reading this
/// engine propagates cites the line that supports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCall {
    /// The callee name as the body spells it, e.g. `CreateFileW`.
    pub callee: String,
    /// The text of each top-level argument, in call order. A call with no
    /// arguments yields none.
    pub args: Vec<String>,
    /// The trimmed source line containing the call.
    pub evidence: String,
}

/// Known library signature propagation over decompiled functions.
///
/// The engine is stateless: every reading comes from the decompiled
/// function it is handed, so one engine serves an entire scan and can be
/// shared across concurrent per-function passes. It holds no Ghidra client
/// of its own — the [`DecompiledFunction`] text is fetched once per
/// function and read by every detector — and it never writes back to the
/// program, only reporting what the body's call sites imply.
///
/// [`DecompiledFunction`]: calxgloss_ghidra::DecompiledFunction
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownTypePropagationEngine;

impl KnownTypePropagationEngine {
    /// An engine with the full standard signature set: the allocator,
    /// string, and handle routines whose parameter contracts propagate to
    /// the arguments sitting at their call sites.
    pub fn new() -> Self {
        Self
    }

    /// The standard signature set the engine propagates through.
    pub fn signatures() -> &'static [KnownSignature] {
        KNOWN_SIGNATURES
    }

    /// Every direct call in a decompiled function body, in source order.
    ///
    /// A call is a plain identifier followed by a balanced argument
    /// list — `CreateFileW(lpFileName, 0x80000000, ...)`. A call through
    /// a function pointer or a vtable slot — `(*(code *)(**param_1))[3](...)`
    /// — names no callee and yields nothing, and neither do the
    /// control-flow keywords Ghidra writes with a parenthesised operand
    /// (`if`, `while`, `for`, `switch`, `case`, `return`, `sizeof`). The
    /// scan runs outside string literals, so a `name(` spelled inside a
    /// format string invents no call, and nested calls are each extracted
    /// separately: `strlen(strcpy(a, b))` yields the outer and the inner
    /// site.
    pub fn extract_calls(&self, func: &DecompiledFunction) -> Vec<ExtractedCall> {
        direct_calls(&func.body)
            .into_iter()
            .map(|call| ExtractedCall {
                callee: call.callee.to_string(),
                args: call.args.into_iter().map(str::to_string).collect(),
                evidence: line_at(&func.body, call.offset),
            })
            .collect()
    }

    /// The signature a callee name resolves to, if any.
    ///
    /// An exact spelling resolves to its entry; failing that, a callee
    /// carrying an `A`/`W` tail resolves to the entry sharing its base —
    /// `CreateFileA` and `CreateFileW` are one family, and the entry
    /// stands for both spellings. The returned [`SignatureMatch`] pairs
    /// the entry with the callee's own spelling, from which
    /// [`SignatureMatch::resolved_args`] settles the character-set
    /// readings; everything else — a bare base name, a longer name, a
    /// suffixed callee beside an entry that carries no tail — resolves
    /// to nothing.
    pub fn match_signature<'a>(&self, callee: &'a str) -> Option<SignatureMatch<'a>> {
        find_signature(callee).map(|signature| SignatureMatch { signature, callee })
    }

    /// The readings the body's known call sites propagate to its
    /// parameters, as [`InferredParamType`] records.
    ///
    /// A call whose callee resolves to a database entry reads each
    /// argument sitting at a position the contract names, at the entry's
    /// own confidence — the C library's contracts at [`LIBC_CONFIDENCE`],
    /// the distinctive Win32 ones at [`WIN32_CONFIDENCE`] — with the
    /// character-set readings settled by the callee's spelling: a
    /// `CreateFileA` site reads its name argument as `char *` where the
    /// `W` twin reads `wchar_t *`. An argument behind a cast still names
    /// the value; an argument that is not one of the function's
    /// parameters — a local, a literal, a nested call — names no
    /// parameter to read, and a position the contract does not read
    /// (`CreateFileW`'s modes and flags) reads nothing sitting there.
    ///
    /// Every reading carries [`InferenceScope::Program`]: the contract
    /// behind it holds at every call site carrying the same value, not
    /// just the site that produced the record. When several call sites
    /// read one parameter differently, the strongest signature wins and
    /// the rest are dropped — a parameter both measured by `strlen` and
    /// closed by `CloseHandle` reads as the handle's `void *` — and a tie
    /// keeps the reading the body showed first.
    pub fn propagate_known_types(&self, func: &DecompiledFunction) -> Vec<InferredParamType> {
        let params = func.parameter_names();
        if params.is_empty() {
            return Vec::new();
        }
        let mut readings: Vec<Reading> = Vec::new();
        for call in direct_calls(&func.body) {
            let Some(signature) = find_signature(call.callee) else {
                continue;
            };
            let matched = SignatureMatch {
                signature,
                callee: call.callee,
            };
            for arg in matched.resolved_args() {
                let Some(text) = call.args.get(arg.position) else {
                    continue;
                };
                let value = strip_casts(text, is_type_word);
                if let Some(index) = params.iter().position(|p| *p == value) {
                    readings.push(Reading {
                        param_index: index,
                        method: InferenceMethod::KnownSignature,
                        inferred_type: arg.inferred_type,
                        confidence: signature.confidence,
                        evidence: line_at(&func.body, call.offset),
                    });
                }
            }
        }
        // One record per parameter: the highest-confidence signature
        // wins and the rest are dropped; a tie keeps the reading the
        // body showed first.
        let winners = Reading::resolve(readings);
        winners
            .into_iter()
            .map(|reading| {
                let param_name = params[reading.param_index].clone();
                reading.into_record(func.name.clone(), param_name, InferenceScope::Program)
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

    #[test]
    fn an_engine_carries_no_state() {
        // One engine serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let engine = KnownTypePropagationEngine::new();
        assert_eq!(engine, KnownTypePropagationEngine);
        assert_eq!(engine.clone(), engine);
    }

    #[test]
    fn an_engine_can_be_shared_across_scans() {
        // The engine is driven concurrently over a program's functions,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KnownTypePropagationEngine>();
    }

    fn signature(name: &str) -> &'static KnownSignature {
        KNOWN_SIGNATURES
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no signature named {name}"))
    }

    fn reading(signature: &KnownSignature, position: usize) -> &'static str {
        signature
            .args
            .iter()
            .find(|arg| arg.position == position)
            .unwrap_or_else(|| {
                panic!(
                    "{} reads no argument at position {position}",
                    signature.name
                )
            })
            .inferred_type
    }

    #[test]
    fn the_database_covers_the_planned_routines_exactly() {
        let mut names: Vec<&str> = KNOWN_SIGNATURES.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let mut planned = vec![
            "CloseHandle",
            "CreateFileW",
            "free",
            "malloc",
            "memcpy",
            "memset",
            "realloc",
            "strcmp",
            "strcpy",
            "strlen",
        ];
        planned.sort_unstable();
        assert_eq!(names, planned);
    }

    #[test]
    fn signature_names_are_unique() {
        // A call site resolves to at most one entry: no two signatures
        // compete for the same callee name.
        let mut names: Vec<&str> = KNOWN_SIGNATURES.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KNOWN_SIGNATURES.len());
    }

    #[test]
    fn argument_positions_increase_within_each_signature() {
        // The per-position readings are listed in call order, each
        // position once, so a lookup can walk them alongside arguments.
        for signature in KNOWN_SIGNATURES {
            for pair in signature.args.windows(2) {
                assert!(
                    pair[0].position < pair[1].position,
                    "{} lists positions out of order",
                    signature.name
                );
            }
        }
    }

    #[test]
    fn the_allocator_contracts_read_buffers_and_sizes() {
        // The block handed to `free` or `realloc` is a heap buffer, and
        // the count beside it is a byte count, not a pointer.
        assert_eq!(reading(signature("free"), 0), BYTE_BUFFER);
        assert_eq!(reading(signature("malloc"), 0), BYTE_COUNT);
        assert_eq!(reading(signature("realloc"), 0), BYTE_BUFFER);
        assert_eq!(reading(signature("realloc"), 1), BYTE_COUNT);
    }

    #[test]
    fn the_string_contracts_read_character_pointers() {
        assert_eq!(reading(signature("strlen"), 0), CHAR_STRING);
        for name in ["strcmp", "strcpy"] {
            assert_eq!(reading(signature(name), 0), CHAR_STRING);
            assert_eq!(reading(signature(name), 1), CHAR_STRING);
        }
    }

    #[test]
    fn the_byte_routines_read_buffers_and_counts_not_strings() {
        assert_eq!(reading(signature("memcpy"), 0), BYTE_BUFFER);
        assert_eq!(reading(signature("memcpy"), 1), BYTE_BUFFER);
        assert_eq!(reading(signature("memcpy"), 2), BYTE_COUNT);
        assert_eq!(reading(signature("memset"), 0), BYTE_BUFFER);
        assert_eq!(reading(signature("memset"), 1), FILL_VALUE);
        assert_eq!(reading(signature("memset"), 2), BYTE_COUNT);
        // A byte buffer is not a NUL-terminated string: neither
        // routine's contract reads a character pointer anywhere.
        for name in ["memcpy", "memset"] {
            assert!(
                signature(name)
                    .args
                    .iter()
                    .all(|arg| arg.inferred_type != CHAR_STRING)
            );
        }
    }

    #[test]
    fn the_handle_contracts_read_handles_and_wide_names() {
        // A HANDLE is an opaque pointer in the decompiler's eyes, and the
        // name behind `CreateFileW` is wide — the reading that tells the
        // `W` twin apart from its `A` spelling.
        assert_eq!(reading(signature("CloseHandle"), 0), BYTE_BUFFER);
        assert_eq!(reading(signature("CreateFileW"), 0), WIDE_STRING);
        // Only the name position is read: the sharing modes, flags, and
        // template handle carry no parameter reading.
        assert_eq!(signature("CreateFileW").args.len(), 1);
    }

    #[test]
    fn every_signature_carries_its_family_confidence() {
        for name in [
            "free", "malloc", "realloc", "strlen", "strcmp", "strcpy", "memcpy", "memset",
        ] {
            assert_eq!(signature(name).confidence, LIBC_CONFIDENCE);
        }
        for name in ["CloseHandle", "CreateFileW"] {
            assert_eq!(signature(name).confidence, WIN32_CONFIDENCE);
        }
        // Distinctive API names outrun the C library's, and both families
        // stay inside the scale the confidence model uses — a fact about
        // the constants themselves, checked at compile time.
        const {
            assert!(WIN32_CONFIDENCE > LIBC_CONFIDENCE);
            assert!(LIBC_CONFIDENCE > 0 && WIN32_CONFIDENCE <= 100);
        };
    }

    #[test]
    fn the_engine_propagates_through_the_standard_signature_set() {
        // The engine's view of its database is the database itself: one
        // shared set, not a per-engine copy.
        assert_eq!(KnownTypePropagationEngine::signatures(), KNOWN_SIGNATURES);
    }

    fn function(signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: signature.into(),
            body: body.into(),
        }
    }

    fn calls(body: &str) -> Vec<ExtractedCall> {
        KnownTypePropagationEngine::new().extract_calls(&function("void FUN_18003ab00(void)", body))
    }

    fn callees(body: &str) -> Vec<String> {
        calls(body).iter().map(|call| call.callee.clone()).collect()
    }

    #[test]
    fn a_direct_call_is_extracted_with_its_arguments() {
        let extracted = calls("  uVar1 = strlen(param_2);");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].callee, "strlen");
        assert_eq!(extracted[0].args, ["param_2"]);
        assert_eq!(extracted[0].evidence, "uVar1 = strlen(param_2);");
    }

    #[test]
    fn a_call_with_no_arguments_carries_an_empty_argument_list() {
        let extracted = calls("  iVar1 = getchar();");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].callee, "getchar");
        assert!(extracted[0].args.is_empty());
    }

    #[test]
    fn nested_calls_are_each_extracted() {
        // The outer call's single argument is the whole inner call; the
        // inner site is extracted on its own, outer first in source order.
        let extracted = calls("  uVar1 = strlen(strcpy(param_2, param_3));");
        assert_eq!(
            callees("  uVar1 = strlen(strcpy(param_2, param_3));"),
            ["strlen", "strcpy"]
        );
        assert_eq!(extracted[0].args, ["strcpy(param_2, param_3)"]);
        assert_eq!(extracted[1].args, ["param_2", "param_3"]);
    }

    #[test]
    fn a_call_spelled_inside_a_string_literal_is_not_a_call() {
        // The scan skips string literals whole, escaped quotes included,
        // so a format string cannot invent a call site.
        let extracted = calls("  printf(\"malloc( not really \\\"free(x)\\\"\");");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].callee, "printf");
    }

    #[test]
    fn control_keywords_are_not_calls_but_their_conditions_hold_calls() {
        let body = "\
if (strlen(param_2) != 0) {
    while (param_1 != 0) {
        switch (param_3) {
        case (1):
            break;
        }
    }
}
return (iVar1);";
        assert_eq!(callees(body), ["strlen"]);
    }

    #[test]
    fn a_member_access_is_not_a_plain_call() {
        // A name reached through `.` or `->` belongs to the object in
        // front of it, not to the program's plain call graph.
        assert!(calls("  obj.foo(param_1);").is_empty());
        assert!(calls("  param_1->callback(param_2);").is_empty());
    }

    #[test]
    fn an_indirect_call_names_no_callee_and_yields_nothing() {
        // A vtable dispatch calls through an expression, not a plain
        // identifier: there is no callee name to look up.
        assert!(calls("  (*(code *)(**param_1))[3](param_1);").is_empty());
    }

    #[test]
    fn arguments_split_at_top_level_commas_only() {
        let extracted = calls(
            "  hLocal = CreateFileW(lpFileName, 0x80000000, 3, (LPVOID)0, 3, 0x80, hTemplateFile);",
        );
        assert_eq!(
            extracted[0].args,
            [
                "lpFileName",
                "0x80000000",
                "3",
                "(LPVOID)0",
                "3",
                "0x80",
                "hTemplateFile",
            ]
        );
        // A nested call's commas and an indexed operand's brackets belong
        // to their argument rather than splitting it.
        let extracted = calls("  foo(bar(a, b), baz[0], d);");
        assert_eq!(extracted[0].args, ["bar(a, b)", "baz[0]", "d"]);
    }

    #[test]
    fn the_evidence_is_the_trimmed_line_holding_the_call() {
        // Ghidra wraps long statements; the call's own line — not the
        // statement's first — is the evidence.
        let extracted = calls("  local_10 = (undefined *)\n      malloc(0x20);");
        assert_eq!(extracted[0].callee, "malloc");
        assert_eq!(extracted[0].evidence, "malloc(0x20);");
    }

    #[test]
    fn a_truncated_body_yields_no_call() {
        // A decompile that stops mid-statement leaves the argument list
        // unbalanced: nothing can be read from a call with no closing
        // paren.
        assert!(calls("  local_10 = malloc(0x20").is_empty());
    }

    #[test]
    fn calls_are_extracted_in_source_order() {
        let body = "\
  free(local_8);
  iVar1 = strlen(param_2);
  CreateFileW(local_10, 0x80000000, 3, (LPVOID)0, 3, 0x80, 0);";
        assert_eq!(callees(body), ["free", "strlen", "CreateFileW"]);
    }

    fn matched(callee: &str) -> Option<SignatureMatch<'_>> {
        KnownTypePropagationEngine::new().match_signature(callee)
    }

    fn resolved(callee: &str) -> Vec<SignatureArg> {
        matched(callee)
            .unwrap_or_else(|| panic!("{callee} resolves to no signature"))
            .resolved_args()
    }

    #[test]
    fn an_exact_callee_resolves_to_its_entry() {
        for name in ["free", "malloc", "strlen", "CloseHandle", "CreateFileW"] {
            let m = matched(name).unwrap_or_else(|| panic!("{name} resolves to no signature"));
            assert_eq!(m.signature, signature(name));
            assert_eq!(m.callee, name);
        }
    }

    #[test]
    fn the_a_twin_resolves_to_the_w_entry() {
        // One contract, two character sets: the body's `CreateFileA`
        // call site is still the `CreateFile` family the database holds.
        let m = matched("CreateFileA").expect("the A twin resolves to the family entry");
        assert_eq!(m.signature, signature("CreateFileW"));
        assert_eq!(m.callee, "CreateFileA");
    }

    #[test]
    fn a_bare_base_name_resolves_to_nothing() {
        // The macro form never reaches a PE import table, and with no
        // tail letter there is no evidence of which character set the
        // arguments carry.
        assert!(matched("CreateFile").is_none());
    }

    #[test]
    fn a_name_beyond_the_family_resolves_to_nothing() {
        // `CreateFile2` and `CreateFileExW` are different contracts, and
        // `myCreateFileW` is a longer name, not a spelling of the family.
        assert!(matched("CreateFile2").is_none());
        assert!(matched("CreateFileExW").is_none());
        assert!(matched("myCreateFileW").is_none());
    }

    #[test]
    fn entries_without_a_tail_match_their_name_only() {
        // An entry that carries no `A`/`W` tail opens no family, so a
        // suffixed callee finds no twin beside it.
        assert!(matched("CloseHandleA").is_none());
        assert!(matched("strlenA").is_none());
        assert!(matched("strcpyW").is_none());
    }

    #[test]
    fn the_w_spelling_keeps_the_wide_reading() {
        assert_eq!(
            resolved("CreateFileW"),
            [SignatureArg {
                position: 0,
                inferred_type: WIDE_STRING,
            }]
        );
    }

    #[test]
    fn the_a_spelling_reads_the_same_position_as_a_character_pointer() {
        // The family match carries the contract; the callee's own tail
        // settles the character set — the `A` twin's name argument is
        // narrow, and propagating the entry's `wchar_t *` to it would
        // be the one reading the split forbids.
        assert_eq!(
            resolved("CreateFileA"),
            [SignatureArg {
                position: 0,
                inferred_type: CHAR_STRING,
            }]
        );
    }

    #[test]
    fn non_character_readings_are_the_entry_s_own() {
        // A buffer, a count, and a fill value say nothing about
        // character sets, so the callee's spelling leaves them alone.
        assert_eq!(
            resolved("malloc"),
            [SignatureArg {
                position: 0,
                inferred_type: BYTE_COUNT,
            }]
        );
        assert_eq!(
            resolved("memset"),
            [
                SignatureArg {
                    position: 0,
                    inferred_type: BYTE_BUFFER,
                },
                SignatureArg {
                    position: 1,
                    inferred_type: FILL_VALUE,
                },
                SignatureArg {
                    position: 2,
                    inferred_type: BYTE_COUNT,
                },
            ]
        );
    }

    #[test]
    fn resolved_readings_keep_positions_and_order() {
        // Settling the character set rewrites readings in place: the
        // positions the contract reads, and their order, are the
        // entry's.
        assert_eq!(
            resolved("CreateFileA"),
            [SignatureArg {
                position: 0,
                inferred_type: CHAR_STRING,
            }]
        );
        let positions: Vec<usize> = resolved("memcpy").iter().map(|arg| arg.position).collect();
        assert_eq!(positions, [0, 1, 2]);
    }

    fn propagated(signature: &str, body: &str) -> Vec<InferredParamType> {
        KnownTypePropagationEngine::new().propagate_known_types(&function(signature, body))
    }

    #[test]
    fn a_known_call_types_the_parameter_at_the_contract_position() {
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  local_10 = malloc(param_1);",
        );
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "size_t");
        assert_eq!(record.method, InferenceMethod::KnownSignature);
        // The contract behind the name holds at every call site carrying
        // the same value, so the reading reaches past this body.
        assert_eq!(record.scope, InferenceScope::Program);
        assert_eq!(record.confidence, LIBC_CONFIDENCE);
        assert_eq!(record.evidence, "local_10 = malloc(param_1);");
        assert!(!record.is_pointer());
        assert!(!record.is_this_pointer());
    }

    #[test]
    fn the_win32_signature_propagates_its_higher_confidence() {
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  bVar1 = CloseHandle(param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, BYTE_BUFFER);
        assert_eq!(records[0].confidence, WIN32_CONFIDENCE);
        assert!(records[0].is_pointer());
    }

    #[test]
    fn the_a_twin_propagates_the_narrow_reading_at_the_family_confidence() {
        // The family match carries the contract and its confidence; the
        // callee's own tail settles the character set.
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 lpFileName)",
            "  hFile = CreateFileA(lpFileName, 0x80000000, 0, 0, 3, 0x80, 0);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_name.as_deref(), Some("lpFileName"));
        assert_eq!(records[0].inferred_type, CHAR_STRING);
        assert_eq!(records[0].confidence, WIN32_CONFIDENCE);
    }

    #[test]
    fn a_position_the_contract_does_not_read_gets_no_reading() {
        // `CreateFileW` reads only its name argument: the sharing modes,
        // flags, and template handle sitting on parameters carry no
        // reading.
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 lpFileName,undefined8 hTemplateFile)",
            "  hFile = CreateFileW(lpFileName, 0x80000000, 3, (LPVOID)0, 3, 0x80, hTemplateFile);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_name.as_deref(), Some("lpFileName"));
        assert_eq!(records[0].inferred_type, WIDE_STRING);
    }

    #[test]
    fn an_argument_behind_a_cast_still_names_the_value() {
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  free((void *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[0].inferred_type, BYTE_BUFFER);
    }

    #[test]
    fn a_local_or_literal_argument_propagates_no_parameter_record() {
        // The contracts still hold over locals and constants, but a
        // parameter record needs a parameter to be about.
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  local_10 = malloc(0x20);\n  free(local_10);\n  strlen(\"name\");",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn an_unknown_callee_propagates_nothing() {
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_18001234(param_1);\n  myCreateFileW(param_1);",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn the_higher_confidence_signature_wins_a_contested_parameter() {
        // Both contracts read position 0 of their own call: the Win32
        // name's reading outruns the C library's, even though the body
        // shows the string call first.
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar1 = strlen(param_1);\n  bVar2 = CloseHandle(param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, BYTE_BUFFER);
        assert_eq!(records[0].confidence, WIN32_CONFIDENCE);
        assert_eq!(records[0].evidence, "bVar2 = CloseHandle(param_1);");
    }

    #[test]
    fn a_tie_keeps_the_reading_the_body_showed_first() {
        // `free` and `strlen` carry the same confidence: the first
        // contract the body shows is the one kept.
        let records = propagated(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  free(param_1);\n  uVar1 = strlen(param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, BYTE_BUFFER);
        assert_eq!(records[0].evidence, "free(param_1);");
    }
}
