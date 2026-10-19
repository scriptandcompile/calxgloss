//! The per-body global-access reading.
//!
//! [`GlobalStateDetector`] reads one decompiled body and yields one
//! access record per sighting of a program global: the global's name,
//! the read/write kind, the access statement as evidence, and the
//! confidence band the sighting scored on the Evidence scale.
//!
//! The global-identification rule is the whole crate's shared rule —
//! the one every consumer reads by, so two crates can never disagree
//! about the same identifier:
//!
//! - A **global** is a plain identifier the decompiler did not name as
//!   one of its own locals — `param_*`, `local_*`, and the typed
//!   variable families (`iVar1`, `uVar2`, `pcVar3`, …) name stack
//!   slots, never program data.
//! - An **access site** is an identifier outside string and char
//!   literals, outside whole calls (a call's entire argument list is
//!   skipped, so a lock object or constant passed to a call names no
//!   access), not the tail or head of a qualified or member name, not
//!   a type word in cast position (`(HANDLE)x`) or in front of a
//!   declared name (`HANDLE handle;`), and not a control keyword —
//!   though a control keyword's *condition* still names its accesses.
//!
//! The kind is spelled by the body: the next non-space bytes open an
//! assignment (`=`, never `==`, or a compound `+=`-style store) or the
//! name sits next to an `++`/`--` bump — that's a write; everything
//! else — a test, a return, a plain copy — reads. The confidence band
//! is spelled by the name: a `DAT_*` spelling is the decompiler's own
//! name for program data, an exact store/load sighting that scores
//! high; any other plain identifier is a shape-only sighting — global
//! position, unproven name — and scores lower. Nothing upgrades
//! itself: repeated sightings of one name each keep their own band.
//!
//! The rule is also exposed as a pure reading — [`global_sites`] names every
//! access site with its byte position and kind, and [`statement_at`] quotes
//! the statement that carried one — so a consumer that keys on where an
//! access sits reads the same rule directly instead of re-deriving it: the
//! sync crate's data-race pairing annotates these sites with its lock-span
//! attribution, and a race finding and a persisted record can then never
//! name different accesses for the same identifier.

use crate::types::{AccessKind, GlobalAccess, GlobalStateFinding};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::{
    NON_CALL_KEYWORDS, closing_paren, is_ident_byte, skip_char, skip_string, skip_ws,
};

/// Confidence of an access whose global is spelled exactly as the
/// decompiler names program data — a `DAT_*` store or load. The name
/// itself is the decompiler's claim that the identifier is a program
/// symbol, and the body spells the access outright, so the reading
/// sits high on the Evidence scale.
pub const EXACT_SPELLING_CONFIDENCE: u8 = 85;

/// Confidence of a shape-only sighting: a plain identifier in global
/// position that the decompiler did not name with its own program-data
/// spelling. The access is real body evidence, but the identifier's
/// status as program data is the decompiler's naming convention
/// inferred from shape, not stated — so the claim sits below every
/// exact spelling, and no later pass raises it from the sighting's own
/// repetition.
pub const SHAPE_ONLY_CONFIDENCE: u8 = 60;

/// The Rust pattern a global read steers a translation toward: the
/// global stays shared program state, read through it rather than
/// frozen into an invented local.
const READ_SUGGESTION: &str = "read the program global through shared state, not an invented local";

/// The Rust pattern a global write steers a translation toward: the
/// global's storage belongs in a struct the translation threads
/// through its units, not in a Rust `static`.
const WRITE_SUGGESTION: &str = "model the program global as shared struct state, not a Rust static";

// The band order is a contract, not a taste call: an exact store/load
// spelling outranks a shape-only sighting. A test in this module pins
// it, and the reading below keys on it.

/// The per-body global-access reading.
///
/// The detector is stateless: every reading comes from the body it is
/// handed, so one detector serves an entire scan and no sighting can
/// upgrade another function's records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalStateDetector;

impl GlobalStateDetector {
    /// A detector with no state — the reading needs none.
    pub fn new() -> Self {
        Self
    }

    /// The global accesses one body makes, in body order: one finding
    /// per access site, tagged by the access kind the body spells,
    /// each carrying the access statement as its evidence and the
    /// band its name spelling scored.
    ///
    /// A name the rule rejects — a decompiler local, a literal's
    /// contents, a call's arguments, a qualified or member spelling, a
    /// type word, a control keyword — contributes no record, so a
    /// body of nothing but rejected names yields nothing.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<GlobalStateFinding> {
        let mut findings = Vec::new();
        for site in global_sites(&func.body) {
            let confidence = if is_exact_spelling(&site.name) {
                EXACT_SPELLING_CONFIDENCE
            } else {
                SHAPE_ONLY_CONFIDENCE
            };
            let record = GlobalAccess {
                function: func.name.clone(),
                global: site.name.clone(),
                evidence: statement_at(&func.body, site.offset),
                confidence: confidence.into(),
                suggestion: match site.kind {
                    AccessKind::Read => READ_SUGGESTION,
                    AccessKind::Write => WRITE_SUGGESTION,
                }
                .to_string(),
            };
            findings.push(match site.kind {
                AccessKind::Read => GlobalStateFinding::GlobalRead(record),
                AccessKind::Write => GlobalStateFinding::GlobalWrite(record),
            });
        }
        findings
    }
}

/// One global access site in a body: the global's name, the byte
/// offset where the name starts, and the access kind the body spells
/// at it.
///
/// The site is the pure reading's atom — position included — for
/// consumers that key on where an access sits: the sync crate's
/// data-race pairing annotates each site with the lock spans that
/// cover it and quotes its statement as evidence, so a race finding
/// and a persisted record name the same accesses by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSite {
    /// The global accessed, spelled exactly as the body spells it.
    pub name: String,
    /// Where the name starts in the body, in bytes.
    pub offset: usize,
    /// Whether the body stores through the global or reads it here.
    pub kind: AccessKind,
}

/// The pure global-identification reading over one body: every global
/// access site, in body order, by the crate's shared rule — the one
/// rule every consumer reads by, so two crates can never disagree
/// about the same identifier. [`GlobalStateDetector::detect`] is this
/// reading turned into findings; a consumer that needs the access
/// positions reads the sites directly and keeps its own attribution
/// on top.
pub fn global_sites(body: &str) -> Vec<GlobalSite> {
    global_name_sites(body)
        .into_iter()
        .map(|(offset, name)| GlobalSite {
            kind: access_kind(body, offset, offset + name.len()),
            name: name.to_string(),
            offset,
        })
        .collect()
}

/// Whether the decompiler named this global with its own program-data
/// spelling — a `DAT_*` symbol — making the sighting an exact store/
/// load rather than a shape-only one.
fn is_exact_spelling(name: &str) -> bool {
    name.starts_with("DAT_")
}

/// Every plain-identifier site in a body that could name program
/// data, in body order: outside string and char literals, not the
/// tail of a member or qualified name, not the head of a qualified
/// name, and not a callee — a call's whole argument list is skipped,
/// so a lock object or an operation constant passed to a call names
/// no access this reading can see. Control keywords keep their parens
/// scanned — `if (DAT_flag)` still names an access — while type words
/// in cast position (`(HANDLE)x`) or in front of a declared name
/// (`HANDLE handle;`) name nothing. Whether the surviving name is a
/// global rather than a local is decided by [`is_decompiler_local`].
fn global_name_sites(body: &str) -> Vec<(usize, &str)> {
    let bytes = body.as_bytes();
    let mut sites = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                // A name preceded by an identifier byte or `.`, `>`,
                // or `:` is the tail of a longer name — a member
                // access or a qualified name — and names nothing.
                if i > 0 && (is_ident_byte(bytes[i - 1]) || b".>:".contains(&bytes[i - 1])) {
                    i += 1;
                    continue;
                }
                let end = name_end(bytes, i);
                let name = &body[i..end];
                if bytes.get(end) == Some(&b':') {
                    // The head of a qualified name — `eqmain::counter`
                    // — and its tail is rejected above, so the whole
                    // spelling names nothing this reading keys on.
                    i = end;
                    continue;
                }
                let open = skip_ws(bytes, end);
                if bytes.get(open) == Some(&b'(') {
                    if NON_CALL_KEYWORDS.contains(&name) {
                        // A control header — `if (DAT_flag)` — is not
                        // a call: only the keyword passes unrecorded,
                        // and the condition still names its accesses.
                        i = end;
                    } else {
                        // A callee: the whole call is skipped,
                        // arguments included.
                        i = closing_paren(body, open).map_or(end, |close| close + 1);
                    }
                    continue;
                }
                if is_cast_word(bytes, i, end) || declares_a_name(bytes, open) {
                    i = end;
                    continue;
                }
                if !is_body_noise(name) && !is_decompiler_local(name) {
                    sites.push((i, name));
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    sites
}

/// The end of the plain identifier run starting at `start` — letters,
/// digits, and underscores only, so a qualified or demangled
/// spelling is never one name this reading keys on.
fn name_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    end
}

/// Whether the name sits in cast position — `(TYPE)expr` or
/// `(TYPE *)expr` — where the decompiler writes a type, not data.
fn is_cast_word(bytes: &[u8], start: usize, end: usize) -> bool {
    if start == 0 || bytes[start - 1] != b'(' {
        return false;
    }
    let mut at = skip_ws(bytes, end);
    while bytes.get(at) == Some(&b'*') {
        at = skip_ws(bytes, at + 1);
    }
    bytes.get(at) == Some(&b')')
}

/// Whether the name is followed by another name — a declaration's
/// `TYPE name;` or a compound type spelling — where the first word
/// is a type and the second is what it names. The declared name never
/// enters the sites on its own: it is preceded by an identifier byte.
fn declares_a_name(bytes: &[u8], open: usize) -> bool {
    bytes
        .get(open)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
}

/// Words a body carries that name no program data: the C control
/// keywords and the decompiler's own literal and label spellings, plus
/// the type words the cast-stripping readings already strip — kept
/// here so a word some reading strips out of a cast is never read as
/// a global either.
fn is_body_noise(word: &str) -> bool {
    matches!(
        word,
        "if" | "else"
            | "while"
            | "do"
            | "for"
            | "switch"
            | "case"
            | "default"
            | "break"
            | "continue"
            | "return"
            | "goto"
            | "sizeof"
            | "true"
            | "false"
            | "NULL"
    ) || word.starts_with("LAB_")
        || is_type_word(word)
}

/// Whether the word is one the decompiler writes as a type, never as
/// program data — the primitive and decompiler-spelled type vocabulary
/// a body carries in casts and declarations.
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
            | "pthread_mutex_t"
            | "pthread_rwlock_t"
            | "pthread_mutexattr_t"
            | "pthread_rwlockattr_t"
    )
}

/// Whether a name is one of the decompiler's own local spellings: a
/// parameter, a stack slot, or one of the typed-variable families
/// (`iVar1`, `uVar2`, `pcVar3`, …) — a `Var` followed by digits and
/// nothing else. Anything else a body names is a program symbol,
/// which is what makes it a global.
fn is_decompiler_local(name: &str) -> bool {
    name.starts_with("param_")
        || name.starts_with("local_")
        || name.find("Var").is_some_and(|at| {
            let suffix = &name[at + 3..];
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Whether the global whose name starts at `offset` and ends at
/// `name_end` is being stored to: the next non-space bytes open an
/// assignment (`=`, never an `==` comparison, or a compound `+=`-style
/// store), or the name sits right next to an `++`/`--` bump on either
/// side. Everything else — a test, a return, a plain copy — reads.
fn access_kind(body: &str, offset: usize, name_end: usize) -> AccessKind {
    let bytes = body.as_bytes();
    let bumps = bytes[name_end..].starts_with(b"++")
        || bytes[name_end..].starts_with(b"--")
        || offset >= 2 && matches!(&bytes[offset - 2..offset], [b'+', b'+'] | [b'-', b'-']);
    if bumps {
        return AccessKind::Write;
    }
    let Some(skip) = bytes[name_end..]
        .iter()
        .position(|b| !b.is_ascii_whitespace())
    else {
        return AccessKind::Read;
    };
    let rest = &bytes[name_end + skip..];
    let assigns = match rest.first() {
        Some(b'=') => !rest.starts_with(b"=="),
        Some(b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^') => rest.get(1) == Some(&b'='),
        _ => false,
    };
    if assigns {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}

/// The one statement of the body around `offset`, trimmed and without
/// its closing `;`: from the terminator that opens it (a `;`, `{`, or
/// `}`) to the `;` that closes it, or the end of the line if the
/// decompiler left the statement open. The statement, not the whole
/// line: the claim is the access itself. A consumer quoting a site's
/// evidence passes the site's own offset.
pub fn statement_at(body: &str, offset: usize) -> String {
    let bytes = body.as_bytes();
    let start = (0..offset)
        .rev()
        .find(|at| matches!(bytes[*at], b';' | b'{' | b'}'))
        .map_or(0, |at| at + 1);
    let end = bytes[offset..]
        .iter()
        .position(|b| *b == b';' || *b == b'\n')
        .map_or(body.len(), |at| offset + at);
    body[start..end].trim().trim_end_matches(';').to_string()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A decompiled function whose body carries `body` under a plain
    /// signature line, the way the seam's decompiles arrive.
    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    /// The records one body yields, as (global, kind, confidence) —
    /// what every reading assertion in this module checks.
    fn readings(body: &str) -> Vec<(String, AccessKind, u8)> {
        GlobalStateDetector::new()
            .detect(&function("FUN_18003ab00", body))
            .into_iter()
            .map(|finding| {
                (
                    finding.global().to_string(),
                    finding
                        .access_kind()
                        .expect("a detector reading always names its access kind"),
                    finding.confidence().value(),
                )
            })
            .collect()
    }

    #[test]
    fn the_exact_spelling_band_outranks_the_shape_only_band() {
        const { assert!(EXACT_SPELLING_CONFIDENCE > SHAPE_ONLY_CONFIDENCE) };
    }

    #[test]
    fn an_exact_dat_store_lands_a_global_write_record() {
        let findings = GlobalStateDetector::new()
            .detect(&function("FUN_18003ab00", "  DAT_180064e80 = param_1;\n"));
        assert_eq!(findings.len(), 1, "one store, one record");
        let finding = &findings[0];
        assert_eq!(finding.kind(), "global_write");
        assert_eq!(finding.function(), "FUN_18003ab00");
        assert_eq!(finding.global(), "DAT_180064e80");
        assert_eq!(finding.evidence(), "DAT_180064e80 = param_1");
        assert_eq!(finding.confidence().value(), EXACT_SPELLING_CONFIDENCE);
        assert!(finding.suggestion().contains("static"));
    }

    #[test]
    fn an_exact_dat_load_lands_a_global_read_record() {
        let findings = GlobalStateDetector::new()
            .detect(&function("FUN_18003ab00", "  uVar1 = DAT_180064e80;\n"));
        assert_eq!(findings.len(), 1, "one load, one record");
        let finding = &findings[0];
        assert_eq!(finding.kind(), "global_read");
        assert_eq!(finding.global(), "DAT_180064e80");
        assert_eq!(finding.evidence(), "uVar1 = DAT_180064e80");
        assert_eq!(finding.confidence().value(), EXACT_SPELLING_CONFIDENCE);
        assert!(finding.suggestion().contains("invented local"));
    }

    #[test]
    fn the_evidence_is_the_statement_that_carried_the_access() {
        // Every record quotes its body: the statement the access sits
        // in, from terminator to terminator — not the whole line and
        // not just the name.
        let findings = GlobalStateDetector::new().detect(&function(
            "FUN_18003ab00",
            "  g_counter += 1;\n  return g_base;\n",
        ));
        assert_eq!(findings.len(), 2, "one store and one read");
        assert_eq!(findings[0].evidence(), "g_counter += 1");
        assert_eq!(findings[1].evidence(), "return g_base");
    }

    #[test]
    fn a_shape_only_sighting_scores_below_the_exact_spelling() {
        let records = readings("  g_counter = g_base;\n");
        assert_eq!(
            records,
            vec![
                (
                    "g_counter".to_string(),
                    AccessKind::Write,
                    SHAPE_ONLY_CONFIDENCE
                ),
                (
                    "g_base".to_string(),
                    AccessKind::Read,
                    SHAPE_ONLY_CONFIDENCE
                ),
            ],
            "a plain identifier in global position is a shape-only sighting at the shape band"
        );
    }

    #[test]
    fn a_shape_only_sighting_never_upgrades_itself() {
        // The same shape-only name sighted three times: each record
        // keeps the shape band — repetition is not corroboration, and
        // no pass here raises a sighting from its own count.
        let records = readings(
            "  g_counter = 1;\n\
             g_counter = g_counter + 1;\n\
             if (g_counter == 2) {\n\
             }\n",
        );
        assert_eq!(records.len(), 4, "every site is a record");
        assert!(
            records
                .iter()
                .all(|(_, _, confidence)| *confidence == SHAPE_ONLY_CONFIDENCE),
            "no sighting upgraded: {records:?}"
        );
    }

    #[test]
    fn an_exact_spelling_keeps_its_band_beside_a_shape_sighting() {
        // One body, both bands: the DAT_ store scores exact, the
        // plain-identifier read stays shape-only — the bands are per
        // record, never averaged across the body.
        let records = readings("  DAT_180064e80 = g_counter;\n");
        assert_eq!(
            records,
            vec![
                (
                    "DAT_180064e80".to_string(),
                    AccessKind::Write,
                    EXACT_SPELLING_CONFIDENCE
                ),
                (
                    "g_counter".to_string(),
                    AccessKind::Read,
                    SHAPE_ONLY_CONFIDENCE
                ),
            ]
        );
    }

    #[test]
    fn a_compound_or_bumping_store_counts_as_a_write() {
        assert_eq!(
            readings(
                "  DAT_a += 1;\n\
             DAT_b++;\n\
             --DAT_c;\n",
            ),
            vec![
                ("DAT_a".to_string(), AccessKind::Write, 85),
                ("DAT_b".to_string(), AccessKind::Write, 85),
                ("DAT_c".to_string(), AccessKind::Write, 85),
            ],
            "compound stores and ++/-- bumps store through the global"
        );
    }

    #[test]
    fn a_comparison_reads_and_never_writes() {
        assert_eq!(
            readings("  if (DAT_flag == 5) {\n  }\n"),
            vec![("DAT_flag".to_string(), AccessKind::Read, 85)],
            "== is a test, not a store"
        );
    }

    #[test]
    fn decompiler_locals_are_never_globals() {
        assert_eq!(
            readings(
                "  param_1 = local_20;\n\
             iVar1 = uVar2;\n\
             pcVar3 = DAT_180064e80;\n",
            ),
            vec![("DAT_180064e80".to_string(), AccessKind::Read, 85)],
            "parameters, stack slots, and the Var families name stack slots, never program data"
        );
    }

    #[test]
    fn a_name_inside_a_string_or_char_literal_names_no_access() {
        assert_eq!(
            readings(
                "  puts(\"DAT_180064e80 = 5\");\n\
             cVar4 = 'g';\n\
             puts(\"g_counter\");\n",
            ),
            Vec::new(),
            "literal contents are text, not accesses"
        );
    }

    #[test]
    fn a_call_argument_names_no_access() {
        assert_eq!(
            readings("  lock(DAT_lock);\n  unlock(DAT_lock);\n"),
            Vec::new(),
            "a call's whole argument list is skipped — a lock object passed to a call names no access"
        );
    }

    #[test]
    fn a_qualified_or_member_name_names_no_access() {
        assert_eq!(
            readings(
                "  eqmain::counter = 5;\n\
             iVar1 = eqmain::counter;\n\
             puVar3->local_8 = DAT_180064e80;\n",
            ),
            vec![("DAT_180064e80".to_string(), AccessKind::Read, 85)],
            "qualified and member spellings name nothing this reading keys on"
        );
    }

    #[test]
    fn a_type_word_or_declaration_names_no_global() {
        assert_eq!(
            readings(
                "  undefined8 uVar1;\n\
             uVar1 = (HANDLE)param_1;\n\
             *(int *)local_18 = 5;\n\
             undefined uVar5;\n",
            ),
            Vec::new(),
            "cast-position type words and declaration types name no access"
        );
    }

    #[test]
    fn a_control_keyword_names_nothing_but_its_condition_still_reads() {
        assert_eq!(
            readings("  if (DAT_flag != 0) {\n    return DAT_flag;\n  }\n"),
            vec![
                ("DAT_flag".to_string(), AccessKind::Read, 85),
                ("DAT_flag".to_string(), AccessKind::Read, 85),
            ],
            "the keyword passes unrecorded; the condition and the return value still name their accesses"
        );
    }

    #[test]
    fn records_come_in_body_order() {
        let records = readings(
            "  DAT_second = 1;\n\
             DAT_first = DAT_second;\n\
             DAT_third = 2;\n",
        );
        assert_eq!(
            records
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["DAT_second", "DAT_first", "DAT_second", "DAT_third"],
            "sites arrive in body order, repeats included"
        );
    }

    #[test]
    fn a_body_with_no_globals_yields_nothing() {
        assert_eq!(
            readings("  int local_8;\n  local_8 = param_1 + 2;\n  return local_8;\n"),
            Vec::new(),
            "a body of locals and type words records nothing"
        );
    }

    #[test]
    fn a_decompiler_local_named_in_two_bodies_is_not_a_global() {
        // The contract the sync pairing's consumption rests on: the
        // rule reads every body the same way, so a stack slot named
        // in two bodies is still just a stack slot — never shared
        // program data one function hands the other.
        let writer =
            GlobalStateDetector::new().detect(&function("FUN_18003ab00", "  local_20 = 5;\n"));
        let reader =
            GlobalStateDetector::new().detect(&function("FUN_18003e750", "  iVar1 = local_20;\n"));
        assert!(
            writer.is_empty() && reader.is_empty(),
            "a stack slot named in two bodies is not a global"
        );
    }

    #[test]
    fn sites_carry_the_position_and_kind_a_consumer_keys_on() {
        // The pure reading is position-inclusive: a consumer that
        // attributes each site to its own spans needs the name,
        // where the name sits, and the kind the body spells.
        let body = "  DAT_counter = 1;\n  uVar1 = DAT_counter;\n";
        let sites = global_sites(body);
        assert_eq!(sites.len(), 2, "one store and one load, in body order");
        assert_eq!(sites[0].name, "DAT_counter");
        assert_eq!(sites[0].kind, AccessKind::Write);
        assert_eq!(
            &body[sites[0].offset..sites[0].offset + sites[0].name.len()],
            "DAT_counter"
        );
        assert_eq!(sites[1].name, "DAT_counter");
        assert_eq!(sites[1].kind, AccessKind::Read);
        assert_eq!(
            &body[sites[1].offset..sites[1].offset + sites[1].name.len()],
            "DAT_counter"
        );
    }

    #[test]
    fn the_statement_a_consumer_quotes_is_the_access_itself() {
        // A locked body writes its acquire and release around the
        // access; the evidence seam quotes the access statement, not
        // the calls beside it.
        let body =
            "  EnterCriticalSection(&guard); DAT_counter = 5; LeaveCriticalSection(&guard);\n";
        let sites = global_sites(body);
        assert_eq!(sites.len(), 1, "the calls name no access, the store does");
        assert_eq!(statement_at(body, sites[0].offset), "DAT_counter = 5");
    }
}
