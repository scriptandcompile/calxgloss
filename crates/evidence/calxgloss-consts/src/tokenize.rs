//! A small pseudo-C tokenizer shared by the three detectors.
//!
//! The detectors read Ghidra's decompiled pseudo-C, and every one of
//! them needs the same thing: integer literals as numbers rather than
//! text, the operators around them as single tokens, and everything
//! that is *not* a literal — the digits inside `local_20`, the text
//! inside a string constant, the address in `FUN_18003ab00` — kept out
//! of the literal stream so a name never masquerades as a constant.
//!
//! The tokenizer is deliberately minimal: identifiers, integer
//! literals (decimal and `0x` hex, with C suffixes), and the operator
//! and punctuation spellings the detectors match on, each carrying the
//! 1-based body line it came from so a finding can quote its evidence.
//! Float literals, string and char literals, and anything non-ASCII
//! are consumed and dropped — no detector reads through them.

/// One lexical unit of a decompiled body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenKind<'a> {
    /// An identifier or keyword spelling, e.g. `local_20` or `switch`.
    Ident(&'a str),
    /// An integer literal's value, e.g. `0x400` → `1024`.
    Int(u64),
    /// An operator or punctuation spelling, e.g. `&=` or `(`.
    Punct(&'a str),
}

/// A [`TokenKind`] together with the 1-based line of the body it came
/// from, so a detector can quote the decompiled lines behind a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token<'a> {
    pub(crate) kind: TokenKind<'a>,
    pub(crate) line: usize,
}

impl<'a> Token<'a> {
    /// Whether this token is a punctuation spelling from `spellings`.
    pub(crate) fn is_punct(&self, spellings: &[&str]) -> bool {
        matches!(self.kind, TokenKind::Punct(p) if spellings.contains(&p))
    }

    /// The identifier spelling, if this token is one.
    pub(crate) fn ident(&self) -> Option<&'a str> {
        match self.kind {
            TokenKind::Ident(name) => Some(name),
            _ => None,
        }
    }

    /// The literal value, if this token is one.
    pub(crate) fn int(&self) -> Option<u64> {
        match self.kind {
            TokenKind::Int(value) => Some(value),
            _ => None,
        }
    }
}

/// The two-character operator spellings, matched before singles so
/// `&=` never reads as `&` followed by `=`.
/// `&&` and `||` are spelled here so a logical operator never reads as
/// a bitwise one to the bitmask detector.
const TWO_CHAR_PUNCT: [&str; 14] = [
    "<<", ">>", "&=", "|=", "^=", "+=", "-=", "*=", "/=", "==", "!=", "->", "&&", "||",
];

/// Whether `c` opens (or continues) a single-character punctuation
/// spelling.
fn is_punct_char(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')'
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'&'
            | b'|'
            | b'^'
            | b'~'
            | b'!'
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'?'
            | b':'
            | b';'
            | b','
            | b'.'
            | b'='
    )
}

/// Whether `c` continues an identifier once it has started.
fn is_ident_continue(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Splits a decompiled body into [`Token`]s.
///
/// String and char literals are consumed whole — their contents never
/// reach the token stream — and digits embedded in identifiers
/// (`local_20`, `FUN_18003ab00`) belong to the identifier, never to a
/// literal. Integer literals carry their numeric value; a literal too
/// large for `u64` is dropped. Float literals are consumed and dropped
/// so their digits do not read as two integers.
pub(crate) fn tokenize(source: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0usize;
    let mut line = 1usize;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'"' || c == b'\'' {
            i = skip_quoted(bytes, i, &mut line);
            continue;
        }
        if c.is_ascii_digit() {
            let (next, literal) = read_number(source, bytes, i);
            if let Some(value) = literal {
                tokens.push(Token {
                    kind: TokenKind::Int(value),
                    line,
                });
            }
            i = next;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Ident(&source[start..i]),
                line,
            });
            continue;
        }
        if i + 1 < bytes.len() {
            let pair = &source[i..i + 2];
            if TWO_CHAR_PUNCT.contains(&pair) {
                tokens.push(Token {
                    kind: TokenKind::Punct(pair),
                    line,
                });
                i += 2;
                continue;
            }
        }
        if is_punct_char(c) {
            tokens.push(Token {
                kind: TokenKind::Punct(&source[i..i + 1]),
                line,
            });
            i += 1;
            continue;
        }
        // Anything else (non-ASCII text, stray bytes) is consumed one
        // byte at a time; no detector reads through it.
        i += 1;
    }
    tokens
}

/// Consumes a string or char literal starting at `start` (its opening
/// quote), honoring backslash escapes, and returns the index just past
/// the closing quote — or the end of input for an unterminated one.
fn skip_quoted(bytes: &[u8], start: usize, line: &mut usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\n' => {
                *line += 1;
                i += 1;
            }
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// Reads one numeric literal at `start`, returning the index just past
/// it and its value — `None` when the literal is a float (consumed and
/// dropped) or too large for `u64`.
fn read_number(source: &str, bytes: &[u8], start: usize) -> (usize, Option<u64>) {
    let (digits_end, radix, digits_start) =
        if bytes[start] == b'0' && start + 1 < bytes.len() && (bytes[start + 1] | 0x20) == b'x' {
            let mut i = start + 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            (i, 16, start + 2)
        } else {
            let mut i = start;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            (i, 10, start)
        };

    // A `.` right after decimal digits makes it a float; consume the
    // fraction (and any exponent) and drop the literal.
    if radix == 10
        && digits_end + 1 < bytes.len()
        && bytes[digits_end] == b'.'
        && bytes[digits_end + 1].is_ascii_digit()
    {
        let mut i = digits_end + 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i + 1 < bytes.len() && (bytes[i] | 0x20) == b'e' && bytes[i + 1].is_ascii_digit() {
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        return (i, None);
    }

    // C integer suffixes (`u`, `l`, `ull`, …) continue the literal.
    let mut end = digits_end;
    while end < bytes.len() && matches!(bytes[end], b'u' | b'U' | b'l' | b'L' | b'f' | b'F') {
        end += 1;
    }

    let value = u64::from_str_radix(&source[digits_start..digits_end], radix).ok();
    (end, value)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<TokenKind<'_>> {
        tokenize(source).into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn integer_literals_carry_their_values() {
        assert_eq!(
            kinds("if (uVar1 & 0x400) x = 1 << 3;"),
            vec![
                TokenKind::Ident("if"),
                TokenKind::Punct("("),
                TokenKind::Ident("uVar1"),
                TokenKind::Punct("&"),
                TokenKind::Int(1024),
                TokenKind::Punct(")"),
                TokenKind::Ident("x"),
                TokenKind::Punct("="),
                TokenKind::Int(1),
                TokenKind::Punct("<<"),
                TokenKind::Int(3),
                TokenKind::Punct(";"),
            ]
        );
    }

    #[test]
    fn identifier_digits_never_read_as_literals() {
        assert_eq!(
            kinds("local_20 = FUN_18003ab00(data1);"),
            vec![
                TokenKind::Ident("local_20"),
                TokenKind::Punct("="),
                TokenKind::Ident("FUN_18003ab00"),
                TokenKind::Punct("("),
                TokenKind::Ident("data1"),
                TokenKind::Punct(")"),
                TokenKind::Punct(";"),
            ]
        );
    }

    #[test]
    fn string_contents_never_reach_the_token_stream() {
        assert_eq!(
            kinds(r#"puts("error 404 in file 7");"#),
            vec![
                TokenKind::Ident("puts"),
                TokenKind::Punct("("),
                TokenKind::Punct(")"),
                TokenKind::Punct(";"),
            ]
        );
    }

    #[test]
    fn compound_operators_read_as_single_tokens() {
        assert_eq!(
            kinds("x &= ~0x10; y |= 2;"),
            vec![
                TokenKind::Ident("x"),
                TokenKind::Punct("&="),
                TokenKind::Punct("~"),
                TokenKind::Int(16),
                TokenKind::Punct(";"),
                TokenKind::Ident("y"),
                TokenKind::Punct("|="),
                TokenKind::Int(2),
                TokenKind::Punct(";"),
            ]
        );
    }

    #[test]
    fn float_literals_are_consumed_and_dropped() {
        assert_eq!(
            kinds("d = 1.5e3; n = 10;"),
            vec![
                TokenKind::Ident("d"),
                TokenKind::Punct("="),
                TokenKind::Punct(";"),
                TokenKind::Ident("n"),
                TokenKind::Punct("="),
                TokenKind::Int(10),
                TokenKind::Punct(";"),
            ]
        );
    }

    #[test]
    fn tokens_carry_their_body_lines() {
        let tokens = tokenize("a = 1;\nb = 2;\n\nc = 3;");
        let lines: Vec<usize> = tokens.iter().map(|t| t.line).collect();
        assert_eq!(lines, vec![1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4]);
    }
}
