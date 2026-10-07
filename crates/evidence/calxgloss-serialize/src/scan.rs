//! Tiny hand-written C++ scanners shared by the detectors.
//!
//! The decompiler output these detectors read is line-oriented and simple
//! enough that regexes buy nothing — and the coding standards bar the
//! `Regex::new(...).expect(...)` idiom in library code (docs/standards.md).
//! Same reasoning as `byteswap.rs`'s `direct_calls`, extended to integer
//! literals for the bitpack and magic detectors.

/// Parse an unsigned integer literal: `0x1F` (hex) or `31` (decimal).
pub(crate) fn parse_uint(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

/// If an integer literal starts at `i` (with no preceding identifier
/// character), return its value and the index just past it.
pub(crate) fn literal_at(line: &[char], i: usize) -> Option<(u64, usize)> {
    if !line[i].is_ascii_digit() {
        return None;
    }
    if i > 0 && (line[i - 1].is_alphanumeric() || line[i - 1] == '_') {
        return None; // tail of an identifier like `iVar2`
    }
    let hex = line[i] == '0' && i + 1 < line.len() && (line[i + 1] == 'x' || line[i + 1] == 'X');
    let digits_from = if hex { i + 2 } else { i };
    let mut end = digits_from;
    while end < line.len() && (line[end].is_ascii_digit() || (hex && line[end].is_ascii_hexdigit()))
    {
        end += 1;
    }
    if end < line.len() && (line[end].is_alphanumeric() || line[end] == '_') {
        return None; // `0x1Fabc` or `12abc` is an identifier, not a literal
    }
    let token: String = line[i..end].iter().collect();
    parse_uint(&token).map(|v| (v, end))
}

/// The integer literal after `i`, skipping whitespace; `None` if the next
/// non-space character does not begin one.
pub(crate) fn literal_after_ws(line: &[char], i: usize) -> Option<(u64, usize)> {
    let mut j = i;
    while j < line.len() && line[j].is_whitespace() {
        j += 1;
    }
    literal_at(line, j)
}

/// Every integer literal on the line.
pub(crate) fn all_literals(line: &[char]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        match literal_at(line, i) {
            Some((v, end)) => {
                out.push(v);
                i = end;
            }
            None => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn parses_hex_and_decimal_literals() {
        assert_eq!(parse_uint("0x1F"), Some(31));
        assert_eq!(parse_uint("0X1f"), Some(31));
        assert_eq!(parse_uint("31"), Some(31));
        assert_eq!(parse_uint("0x"), None);
        assert_eq!(parse_uint(""), None);
        assert_eq!(parse_uint("12abc"), None);
    }

    #[test]
    fn literals_ignore_identifier_tails() {
        // `iVar2` is an identifier with a digit tail, and `0x1Fzz` is
        // not a well-formed literal; neither may yield a value. A full
        // hex run like `0x1Fabc` is a legitimate literal, though.
        assert_eq!(all_literals(&chars("iVar2 = 3;")), vec![3]);
        assert_eq!(all_literals(&chars("x = 0x1Fzz;")), Vec::<u64>::new());
        assert_eq!(all_literals(&chars("x = 0x1Fabc;")), vec![0x1fabc]);
    }

    #[test]
    fn collects_every_literal_on_the_line() {
        assert_eq!(
            all_literals(&chars("if (uVar1 == 0x89504E47) {")),
            vec![0x89504E47]
        );
        assert_eq!(all_literals(&chars("b = (a >> 8) & 0xFF;")), vec![8, 0xFF]);
    }

    #[test]
    fn literal_after_ws_skips_spaces() {
        let line = chars(">>   0x10");
        assert_eq!(literal_after_ws(&line, 2), Some((0x10, 9)));
        let line = chars(">> foo");
        assert_eq!(literal_after_ws(&line, 2), None);
    }
}
