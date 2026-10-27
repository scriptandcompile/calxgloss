//! Shared `Display` pattern for serde-label enums.
//!
//! Several crates hold `#[serde(rename_all = "snake_case")]` enums whose
//! `Display` impl exists only to print the serde label. The point: the
//! stored JSON and the prompt text use the same word. Before this macro,
//! each enum hand-wrote the same `match`/`write_str` boilerplate; this
//! macro states the pattern once.
//!
//! The labels are spelled out in the code instead of generated from the
//! variant names, so grepping for a label finds it next to the JSON it
//! produces. The generated `match` covers every variant: adding a variant
//! without a label is a compile error, not a rendering that silently goes
//! missing.

/// Implements `Display` for an enum by writing each variant's label.
///
/// Intended for `#[serde(rename_all = "snake_case")]` enums whose `Display`
/// should print exactly the label serde persists; each `$label` must match
/// what serde writes for that variant.
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

    /// The point of the pattern: `Display` prints exactly what serde
    /// persists. If the two ever disagree on a label, this test catches
    /// the bug.
    #[test]
    fn display_re_emits_the_serde_label() {
        for variant in [Sample::OneWord, Sample::TwoWords] {
            let label = serde_json::to_value(variant).unwrap();
            assert_eq!(variant.to_string(), label.as_str().unwrap());
        }
    }
}
