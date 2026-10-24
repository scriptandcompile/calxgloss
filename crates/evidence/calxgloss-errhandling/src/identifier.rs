//! Identifier-boundary matching shared by the body-text detectors.
//!
//! The named-handler, exception-API, `RaiseException`, and goto-
//! cleanup readings all ask the same question of one body line: does
//! it name a known API or thunk *as an identifier*, not as a fragment
//! of some longer name? A plain substring search would read
//! `my_except_handler3_wrapper` or a `RaiseExceptionFilter` call as
//! the sighting it wants; this module gives the name-based detectors
//! one boundary rule and one call-shape rule instead of four
//! near-identical ones.

/// Whether `line` names `name` as a whole identifier, returning the
/// body text immediately following the identifier — what a
/// caller-shaped detector inspects for its `(` — as an [`Option`].
///
/// The boundary rule has two halves. Nothing identifier-shaped may
/// *follow* the occurrence: the next character must not be an
/// alphanumeric or underscore, which is what keeps
/// `RaiseExceptionFilter` and `_except_handler4_common` (a different
/// routine) from reading as the names they start with. Nothing but
/// underscores may *precede* it: the import decoration the engine
/// sometimes carries (`__except_handler4` beside `_except_handler4`)
/// is a prefix of underscores only, while `my_` or `imp_` prefixes
/// mark a different identifier entirely. A name that is itself
/// underscore-led (`__except_handler3`) therefore matches its own
/// spelled form and deeper-underscore spellings, and nothing else.
pub(crate) fn named_token<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0usize;
    while let Some(idx) = line[from..].find(name) {
        let start = from + idx;
        let end = start + name.len();
        from = end;

        // The character after the occurrence must not continue an
        // identifier, or the body named a longer thing than we spell.
        if line[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        // Everything before the occurrence, back through any run of
        // underscores, must end on a non-identifier character (or the
        // line's start).
        let before = line[..start].trim_end_matches('_');
        if before
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        return Some(&line[end..]);
    }
    None
}

/// Whether the text following a name opens its call — the `(` after
/// any run of spaces and tabs (and a line-ending carriage return
/// left behind by a CRLF body). A wrapped call whose paren opens on
/// the *next* line is a miss the line-local reading accepts: the
/// decompiler spells calls on one line, and the pinned contract is
/// that a bare name sighting claims nothing.
pub(crate) fn starts_call(after: &str) -> bool {
    after.trim_start_matches([' ', '\t', '\r']).starts_with('(')
}

/// Whether `s` opens with `word` as a whole word, not as the prefix
/// of a longer name — the keyword-shape rule the goto-cleanup ladder
/// reads its guard heads and constant returns through, and the
/// failure-code reading reads its statement shapes through.
pub(crate) fn starts_word(s: &str, word: &str) -> bool {
    s.starts_with(word)
        && !s[word.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The offset of `word` as a whole word inside `hay`, if it stands
/// anywhere in it. A keyword standing mid-line — the one-line
/// `if (cond) return X;` spelling — still marks what follows it, so
/// the reading of what the statement carries reads from there.
pub(crate) fn find_word(hay: &str, word: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(offset) = hay[from..].find(word) {
        let start = from + offset;
        let end = start + word.len();
        from = end;
        let before_clear = !hay[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let after_clear = !hay[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if before_clear && after_clear {
            return Some(start);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_occurrence_is_a_sighting() {
        let line = "  __except_handler3(param_1, param_2);";
        let after = named_token(line, "__except_handler3").expect("the spelled name matches");
        assert_eq!(after, "(param_1, param_2);");
    }

    #[test]
    fn underscore_prefixed_spellings_qualify() {
        // The engine's decoration adds underscores; `_except_handler4`
        // also reads inside a double-underscore `__except_handler4`.
        assert!(named_token("  _except_handler4;", "_except_handler4").is_some());
        assert!(named_token("  __except_handler4;", "_except_handler4").is_some());
        assert!(named_token("  ___except_handler4();", "_except_handler4").is_some());
    }

    #[test]
    fn identifier_continuations_do_not_qualify() {
        // The longer routine's name starts with ours; it is a
        // different function and claims nothing.
        assert!(named_token("  _except_handler4_common(a, b);", "_except_handler4").is_none());
        assert!(named_token("  RaiseExceptionFilter(0);", "RaiseException").is_none());
    }

    #[test]
    fn identifier_prefixes_do_not_qualify() {
        // Only underscores may precede the name: a decorated or
        // hand-named variant is its own identifier.
        assert!(named_token("  my_except_handler3();", "_except_handler3").is_none());
        assert!(named_token("  _imp__except_handler3();", "_except_handler3").is_none());
    }

    #[test]
    fn undecorated_spellings_read_through_underscore_decoration() {
        // The tolerance is one-directional on purpose: an
        // underscore-led body spelling matches its own undecorated
        // name (the decoration is underscores only), while a name
        // with letters before it is a different identifier.
        assert!(named_token("  __except_handler3();", "except_handler3").is_some());
        assert!(named_token("  my_except_handler3();", "except_handler3").is_none());
    }

    #[test]
    fn punctuation_beside_the_name_qualifies_it() {
        // Non-identifier neighbours — call parens, spaces, commas —
        // leave the occurrence standing as a whole identifier.
        assert!(named_token("  filter = _CxxFrameHandler3;", "_CxxFrameHandler3").is_some());
        assert!(named_token("  RaiseException (0x1);", "RaiseException").is_some());
    }

    #[test]
    fn a_call_paren_opens_after_the_spacing_the_decompiler_spells() {
        assert!(starts_call("(param_1);"));
        assert!(starts_call(" (param_1);"));
        assert!(starts_call("  \t(x);"));
        assert!(starts_call("\r(x);"));
        // The name standing alone, or a paren spelled on the next
        // line by a wrapped call, is not the call shape.
        assert!(!starts_call(";"));
        assert!(!starts_call(" = &handler;"));
    }

    #[test]
    fn a_head_word_reads_the_keyword_and_nothing_longer() {
        assert!(starts_word("if (uVar == 0) {", "if"));
        assert!(starts_word("else if (bad) {", "else"));
        // A keyword-shaped prefix of a longer name is a different
        // word entirely: the goto-cleanup crate's own guard reading
        // refuses `iffy` just as this rule does.
        assert!(!starts_word("iffy = 1;", "if"));
        assert!(!starts_word("_return;", "return"));
    }

    #[test]
    fn a_keyword_mid_line_is_found_at_its_offset() {
        // The one-line `if (cond) return X;` spelling puts the
        // keyword mid-line; the reading of what follows starts there.
        assert_eq!(find_word("  if (bad) return 0;", "return"), Some(11));
        assert_eq!(find_word("  return_value = 1;", "return"), None);
        assert_eq!(find_word("  goto joined_r0x123;", "return"), None);
    }
}
