//! STL/MFC shape detection over recovered names.
//!
//! C++ standard-library and MFC types — `basic_string`/`CString`, `vector`,
//! `list`, the `map`/`set` family, smart pointers — arrive in the type
//! database like any other class. They show up as Type Manager names, as
//! RTTI-demangled vtable class names, and as the suggested types of
//! inferred fields.
//!
//! The translator wastes effort inventing raw layouts for types that map
//! directly onto Rust's `String`/`Vec<T>`/`BTreeMap<K,V>`. So the scan
//! flags records whose *name* matches a known shape, and records the
//! matched family as an [`StlKind`].
//!
//! Detection is name-pattern matching, not layout analysis. [`detect`]
//! matches a recovered name against the family token lists below; it
//! never inspects fields or sizes. The result is flag-only: a flagged
//! record stays in every section and answers every lookup. The reason is
//! that a name is evidence, not proof. The program may define its own
//! `MySet`, and an STL type hidden behind a typedef alias has no name
//! shape to match.

use calxgloss_types::display_serde_label;
use serde::{Deserialize, Serialize};

/// The STL/MFC family a recovered name's shape belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StlKind {
    /// A string type: `basic_string`/`wstring`, MFC/ATL `CString`, or a
    /// plain C `char *`/`wchar_t *`.
    String,
    /// A dynamic array: `vector`.
    Vector,
    /// A linked list: `list`, `forward_list`.
    List,
    /// An associative container: `map`/`set` and their `multi`/`unordered`/
    /// `hash` variants.
    Map,
    /// An owning or observing smart pointer: `shared_ptr`, `unique_ptr`,
    /// `weak_ptr`, `auto_ptr`.
    SmartPointer,
}

display_serde_label!(StlKind {
    String => "string",
    Vector => "vector",
    List => "list",
    Map => "map",
    SmartPointer => "smart_pointer",
});

/// The family token lists, matched case-sensitively.
///
/// The spellings cover two demangler dialects. One is what Ghidra's own
/// demangler writes into the Type Manager (`vector<int,std::allocator<int>_ >`).
/// The other is what this crate's RTTI demangler produces for vtable
/// class names: there the template segments arrive reversed and
/// `$`-prefixed (`std::VWidget::$vector`), and the boundary rule below
/// accepts that form. Generic tokens stay lowercase, so a program's own
/// `Set`/`List`/`String` class is not mistaken for the standard-library
/// one. `CString` is the one mixed-case token because that is how MFC
/// spells it.
const SHAPES: &[(StlKind, &[&str])] = &[
    (
        StlKind::String,
        &[
            "basic_string",
            "wstring",
            "string",
            "cstring",
            "CString",
            "char *",
            "char*",
            "wchar_t *",
            "wchar_t*",
        ],
    ),
    (StlKind::Vector, &["vector"]),
    (StlKind::List, &["list", "forward_list"]),
    (
        StlKind::Map,
        &[
            "map",
            "multimap",
            "unordered_map",
            "hash_map",
            "set",
            "multiset",
            "unordered_set",
            "hash_set",
        ],
    ),
    (
        StlKind::SmartPointer,
        &["shared_ptr", "unique_ptr", "weak_ptr", "auto_ptr"],
    ),
];

/// The family whose shape `name` matches, or `None` when no shape does.
///
/// Only the *head* of the name — the part before the first `<` — is
/// matched. Template arguments say what a type contains, not what the
/// type is, so `std::less<std::string>` and `pair<char *,int>` match no
/// shape even though their arguments do.
///
/// A token matches only as a whole word: the characters on either side
/// (if any) must not be identifier characters. So `offset` contains no
/// `set`, `listing` contains no `list`, and `my_set` contains no `set`,
/// while `std::vector<…>`, `$vector`, and `char *` all match. Longer
/// tokens need no special ordering: `multimap` contains an embedded `map`,
/// but the boundary rule blocks it, so the `multimap` token produces the
/// match.
///
/// When a head matches several families, the family whose token appears
/// *earliest* wins, because the leading token names the outer type.
pub fn detect(name: &str) -> Option<StlKind> {
    let head = name.split('<').next().unwrap_or(name);
    let mut best: Option<(usize, StlKind)> = None;
    for (kind, tokens) in SHAPES {
        for token in *tokens {
            if let Some(at) = find_word(head, token)
                && best.is_none_or(|(earliest, _)| at < earliest)
            {
                best = Some((at, *kind));
            }
        }
    }
    best.map(|(_, kind)| kind)
}

/// The offset of the first whole-word occurrence of `token` in `haystack`,
/// delimited by non-identifier characters (or the string ends).
fn find_word(haystack: &str, token: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(token) {
        let start = from + offset;
        let end = start + token.len();
        let before_clear = start == 0 || !is_identifier_byte(bytes[start - 1]);
        let after_clear = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if before_clear && after_clear {
            return Some(start);
        }
        from = end;
    }
    None
}

/// Whether `byte` continues an identifier. The delimiters that *do*
/// separate shape tokens are `:`, `$`, `<`, `,`, spaces, and string ends.
fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stl_kind_displays_its_serde_label() {
        for kind in [
            StlKind::String,
            StlKind::Vector,
            StlKind::List,
            StlKind::Map,
            StlKind::SmartPointer,
        ] {
            let label = serde_json::to_value(kind).unwrap();
            assert_eq!(kind.to_string(), label.as_str().unwrap());
        }
    }

    #[test]
    fn detects_string_shapes() {
        for name in [
            "basic_string<char,std::char_traits<char>,std::allocator<char> >",
            "basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t> >",
            "std::string",
            "std::wstring",
            "CString",
            "ATL::CString",
            "char *",
            "wchar_t *",
        ] {
            assert_eq!(detect(name), Some(StlKind::String), "{name}");
        }
    }

    #[test]
    fn detects_container_shapes() {
        assert_eq!(
            detect("vector<int,std::allocator<int>_ >"),
            Some(StlKind::Vector)
        );
        assert_eq!(detect("std::vector<Widget>"), Some(StlKind::Vector));
        assert_eq!(detect("list<Widget>"), Some(StlKind::List));
        assert_eq!(detect("std::forward_list<int>"), Some(StlKind::List));
        assert_eq!(detect("map<int,Widget>"), Some(StlKind::Map));
        assert_eq!(detect("set<char>"), Some(StlKind::Map));
        assert_eq!(detect("std::multimap<int,int>"), Some(StlKind::Map));
        assert_eq!(detect("std::unordered_set<int>"), Some(StlKind::Map));
    }

    #[test]
    fn detects_smart_pointer_shapes() {
        assert_eq!(detect("shared_ptr<Widget>"), Some(StlKind::SmartPointer));
        assert_eq!(
            detect("std::unique_ptr<Widget>"),
            Some(StlKind::SmartPointer)
        );
        assert_eq!(detect("weak_ptr<Widget>"), Some(StlKind::SmartPointer));
    }

    #[test]
    fn detects_the_rtti_demangler_s_spellings() {
        // Pin the detector against the demangler's real output, not a
        // hand-written spelling. `.?AV?$vector@VWidget@@std@@` demangles
        // to template segments reversed and `$`-prefixed, and the
        // boundary rule still finds the token.
        let vector = crate::vtable::demangle_rtti_name(".?AV?$vector@VWidget@@std@@")
            .expect("a class descriptor should demangle");
        assert_eq!(detect(&vector), Some(StlKind::Vector), "{vector}");
        let string = crate::vtable::demangle_rtti_name(
            ".?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@",
        )
        .expect("a class descriptor should demangle");
        assert_eq!(detect(&string), Some(StlKind::String), "{string}");
    }

    #[test]
    fn the_earliest_shape_token_names_the_family() {
        // A container of strings is a container: the head names the outer
        // type, not the template argument's family.
        assert_eq!(detect("std::vector<char *>"), Some(StlKind::Vector));
        assert_eq!(detect("map<wstring,int>"), Some(StlKind::Map));
        assert_eq!(detect("shared_ptr<CString>"), Some(StlKind::SmartPointer));
    }

    #[test]
    fn template_arguments_alone_never_name_a_family() {
        // A wrapper whose own head has no shape stays unflagged, even
        // when its template arguments do.
        assert_eq!(detect("std::less<std::string>"), None);
        assert_eq!(detect("pair<char *,int>"), None);
        assert_eq!(detect("allocator<char *>"), None);
    }

    #[test]
    fn program_names_are_not_flagged() {
        for name in [
            "Widget",
            "IMAGE_DOS_HEADER",
            "offset",
            "listing",
            "dataset",
            "my_set",
            "MyString",
            "StringStream",
            "CMapStringToOb",
            "ImageList",
            "char[2]",
            "dword",
        ] {
            assert_eq!(detect(name), None, "{name}");
        }
    }

    #[test]
    fn decompiler_default_names_are_not_flagged() {
        // Both analysis engines create unnamed-function placeholders:
        // Ghidra writes `FUN_…`/`LAB_…`/`SUB_…`, and Kuna writes the
        // lowercase `sub_…`/`dat_…`/`label_…`. These are address
        // spellings, not types. No shape token can whole-word match
        // inside the bare hex tail, so the detector stays silent on
        // either dialect's names.
        for name in [
            "FUN_1800861f0",
            "LAB_1800010b7",
            "SUB_140002490",
            "sub_140002490",
            "dat_140003e8c",
            "label_1400010b7",
        ] {
            assert_eq!(detect(name), None, "{name}");
        }
    }
}
