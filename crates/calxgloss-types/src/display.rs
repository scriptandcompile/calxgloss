//! Shared `Display` pattern for serde-label enums.
//!
//! Several crates hold `#[serde(rename_all = "snake_case")]` enums whose
//! `Display` impl exists only to re-emit the serde label — the persisted
//! JSON and the prompt rendering speak the same word. Each one hand-wrote
//! the same `match`/`write_str` boilerplate; this macro states the pattern
//! once.
//!
//! The labels are spelled out rather than derived from the variant names
//! so they stay greppable next to the JSON they produce, and the generated
//! `match` is exhaustive: adding a variant without a label is a compile
//! error, not a silently missing rendering.

/// Implements `Display` for an enum by writing each variant's label.
///
/// Intended for `#[serde(rename_all = "snake_case")]` enums whose `Display`
/// re-emits the serde label; each `$label` must match what serde writes for
/// that variant.
///
/// ```
/// use calxgloss_types::display_serde_label;
///
/// #[derive(serde::Serialize)]
/// #[serde(rename_all = "snake_case")]
/// enum Sample {
///     OneWord,
///     TwoWords,
/// }
///
/// display_serde_label!(Sample {
///     OneWord => "one_word",
///     TwoWords => "two_words",
/// });
///
/// assert_eq!(Sample::TwoWords.to_string(), "two_words");
/// ```
#[macro_export]
macro_rules! display_serde_label {
    ($ty:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($label),)+
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Sample {
        OneWord,
        TwoWords,
    }

    display_serde_label!(Sample {
        OneWord => "one_word",
        TwoWords => "two_words",
    });

    /// The whole point of the pattern: `Display` says exactly what serde
    /// persists, so a label drift between the two is a bug the test catches.
    #[test]
    fn display_re_emits_the_serde_label() {
        for variant in [Sample::OneWord, Sample::TwoWords] {
            let label = serde_json::to_value(variant).unwrap();
            assert_eq!(variant.to_string(), label.as_str().unwrap());
        }
    }
}
