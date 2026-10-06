//! Nine-category string classification.
//!
//! [`StringClassifyEngine`] reads what a program string is *for* — a
//! `sprintf` format string, a config-file path, an error message shown to
//! the user — by matching it against a pattern set per category in a fixed
//! priority order, FormatString > FilePath > ResourceName > Error >
//! Network > DebugLog > UserVisible > InternalIdentifier > Generic. A
//! string that matches several pattern sets lands in the most informative
//! bucket deterministically: the order is the engine's, not the pattern
//! sets', so two scans of the same program classify identically.
//!
//! Each category carries a set of regex patterns matched case-insensitively
//! against the string's value ([`CategoryPatterns`], with
//! [`default_patterns`](CategoryPatterns::default_patterns) carrying the
//! standard sets). The whole set is swappable —
//! [`with_patterns`](StringClassifyEngine::with_patterns) replaces every
//! category at once, the way the sync detector setters swap name sets —
//! so tests and tuned scans drive classification with their own patterns.
//! [`infer_purpose`] turns a category into the one-line intent the prompt
//! shows beside it.

use crate::format_str::extract_format_hints;
use crate::types::{FormatHint, StringClassification};
use regex::Regex;
use serde::{Deserialize, Serialize};

// ============================================================
// Pattern sets
// ============================================================

/// The pattern set per category the classifier matches strings against.
///
/// Every pattern is a regex tried case-insensitively against the string's
/// value; a category claims the string when any of its patterns match.
/// `Generic` has no set — it is the fallback when no category claims the
/// string. The sets are plain data so a caller can supply them whole
/// through [`StringClassifyEngine::with_patterns`]; a pattern that fails to
/// compile is dropped with a warning rather than failing the build.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryPatterns {
    /// Patterns for [`FormatString`](StringClassification::FormatString).
    pub format_string: Vec<String>,
    /// Patterns for [`FilePath`](StringClassification::FilePath).
    pub file_path: Vec<String>,
    /// Patterns for [`ResourceName`](StringClassification::ResourceName).
    pub resource_name: Vec<String>,
    /// Patterns for [`Error`](StringClassification::Error).
    pub error: Vec<String>,
    /// Patterns for [`Network`](StringClassification::Network).
    pub network: Vec<String>,
    /// Patterns for [`DebugLog`](StringClassification::DebugLog).
    pub debug_log: Vec<String>,
    /// Patterns for [`UserVisible`](StringClassification::UserVisible).
    pub user_visible: Vec<String>,
    /// Patterns for [`InternalIdentifier`](StringClassification::InternalIdentifier).
    pub internal_identifier: Vec<String>,
}

impl CategoryPatterns {
    /// The standard pattern sets every scan runs with unless swapped.
    ///
    /// The patterns are heuristics over the spellings Ghidra-decompiled
    /// binaries actually carry — Windows paths and extensions, registry
    /// keys, `printf` specifiers, error and log vocabulary, dialog words,
    /// identifier shapes — ordered by the engine's fixed priority, not by
    /// the order of these fields.
    pub fn default_patterns() -> Self {
        Self {
            format_string: vec![
                r"%[-+ #0]*[0-9]*(\.[0-9]+)?[diouxXeEfFgGaAcsp]".to_string(),
            ],
            file_path: vec![
                r"(?i)^[a-z]:[\\/]"
                    .to_string(),
                r"(?i)\\[\w.$%-]+\\[\w.$%\\-]*".to_string(),
                r"(?i)\.(dll|exe|ini|txt|cfg|dat|sys|ocx|bin|tmp|log|json|xml|htm|html|lib)$"
                    .to_string(),
                // A bare filename with an unknown extension: no slashes
                // and exactly one dot, so domains and URLs fall through
                // to Network instead of reading as paths.
                r"(?i)^[^/\\.]*\.[a-z]{2,4}$".to_string(),
            ],
            resource_name: vec![
                r"(?i)^(HKEY_|SOFTWARE\\|CurrentVersion\\)".to_string(),
                r"(?i)\.(bmp|png|jpg|jpeg|gif|wav|mp3|ogg|ttf|cur|ico|ani|res)$".to_string(),
                r"(?i)^(ID[RI]_|IDD_|MAKEINTRESOURCE)".to_string(),
            ],
            error: vec![
                r"(?i)\b(error|errors|failed|failure|fail(s|ed)?|cannot|can't|unable|invalid|corrupt|denied|refused|unsupported|not found|missing)\b"
                    .to_string(),
            ],
            network: vec![
                r"(?i)\b(https?|ftp|wss?)://".to_string(),
                r"(?i)\b(winsock|socket|hostname|proxy|url|uri)\b".to_string(),
                r"(?i)\bport[ :=][0-9]+".to_string(),
                r"(?i)^[a-z0-9.-]+\.(com|net|org)\b".to_string(),
            ],
            debug_log: vec![
                r"(?i)\b(debug|trace|assert|warning|warn|verbose|logging|dump)\b".to_string(),
            ],
            user_visible: vec![
                r"(?i)\b(ok|cancel|yes|no|please|press|click|welcome|login|log in|logout|password|username|quit|exit|menu|options|settings|help)\b"
                    .to_string(),
            ],
            internal_identifier: vec![
                r"^[A-Za-z_][A-Za-z0-9_]*$".to_string(),
                r"(?i)^(FUN|DAT|LAB|thunk_|_imp_)".to_string(),
                r"^[A-Z][A-Z0-9_]{2,}$".to_string(),
                r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$".to_string(),
            ],
        }
    }
}

/// The compiled pattern sets, in the engine's fixed priority order.
#[derive(Debug, Clone)]
struct CompiledPatterns {
    /// (category, its compiled patterns) in priority order; `Generic` is
    /// absent — it is the fallback, not a pattern set.
    ordered: Vec<(StringClassification, Vec<Regex>)>,
}

impl CompiledPatterns {
    fn compile(patterns: &CategoryPatterns) -> Self {
        // The priority order is the engine's, fixed here once; swapping
        // pattern sets can never reorder the buckets.
        let sets = [
            (StringClassification::FormatString, &patterns.format_string),
            (StringClassification::FilePath, &patterns.file_path),
            (StringClassification::ResourceName, &patterns.resource_name),
            (StringClassification::Error, &patterns.error),
            (StringClassification::Network, &patterns.network),
            (StringClassification::DebugLog, &patterns.debug_log),
            (StringClassification::UserVisible, &patterns.user_visible),
            (
                StringClassification::InternalIdentifier,
                &patterns.internal_identifier,
            ),
        ];
        let ordered = sets
            .into_iter()
            .map(|(category, sources)| {
                let compiled = sources
                    .iter()
                    .filter_map(|source| match Regex::new(source) {
                        Ok(regex) => Some(regex),
                        Err(error) => {
                            tracing::warn!(
                                pattern = %source,
                                error = %error,
                                "Classification pattern does not compile; skipping it"
                            );
                            None
                        }
                    })
                    .collect();
                (category, compiled)
            })
            .collect();
        Self { ordered }
    }
}

// ============================================================
// Engine
// ============================================================

/// Nine-category string classification over one program's strings.
///
/// The engine carries the compiled pattern sets and no per-scan state, so
/// one instance classifies a whole scan. [`new`](Self::new) starts with no
/// patterns — every string reads as `Generic` until sets arrive — and
/// [`with_default_patterns`](Self::with_default_patterns) builds the
/// standard classifier. [`with_patterns`](Self::with_patterns) swaps every
/// set whole.
#[derive(Debug, Clone)]
pub struct StringClassifyEngine {
    patterns: CompiledPatterns,
}

impl Default for StringClassifyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StringClassifyEngine {
    /// A classifier with no patterns configured: every string it is
    /// handed reads as [`Generic`](StringClassification::Generic) until
    /// pattern sets arrive through [`with_patterns`](Self::with_patterns)
    /// or [`with_default_patterns`](Self::with_default_patterns).
    pub fn new() -> Self {
        Self {
            patterns: CompiledPatterns::compile(&CategoryPatterns::default()),
        }
    }

    /// A classifier scanning against the standard pattern sets —
    /// [`CategoryPatterns::default_patterns`].
    pub fn with_default_patterns() -> Self {
        Self::with_patterns(CategoryPatterns::default_patterns())
    }

    /// A classifier scanning against exactly `patterns`, every category's
    /// set swapped whole.
    pub fn with_patterns(patterns: CategoryPatterns) -> Self {
        Self {
            patterns: CompiledPatterns::compile(&patterns),
        }
    }

    /// Classify one string value into its category.
    ///
    /// The categories are tried in the fixed priority order — format
    /// string, file path, resource name, error, network, debug log,
    /// user-visible text, internal identifier, generic — and the first
    /// whose pattern set matches claims the string, so a string that
    /// matches several sets lands in the most informative bucket
    /// deterministically. A string no set matches is
    /// [`Generic`](StringClassification::Generic).
    pub fn classify(&self, value: &str) -> StringClassification {
        for (category, regexes) in &self.patterns.ordered {
            if regexes.iter().any(|regex| regex.is_match(value)) {
                return *category;
            }
        }
        StringClassification::Generic
    }

    /// The one-line intent a classification implies, shown beside the
    /// category in the prompt — e.g. an error string reads as
    /// `error message shown to the user`.
    pub fn infer_purpose(&self, classification: StringClassification) -> &'static str {
        match classification {
            StringClassification::FormatString => "format string for a printf-style call",
            StringClassification::FilePath => "file or registry path",
            StringClassification::ResourceName => "resource or registry name",
            StringClassification::Error => "error message shown to the user",
            StringClassification::Network => "network address or protocol string",
            StringClassification::DebugLog => "debug or log message",
            StringClassification::UserVisible => "text shown to the user",
            StringClassification::InternalIdentifier => "internal identifier or symbol name",
            StringClassification::Generic => "general string data",
        }
    }

    /// Parse the format specifiers out of a format string into
    /// [`FormatHint`] records, in argument order.
    ///
    /// Delegates to the format-string engine's documented table
    /// ([`extract_format_hints`](crate::format_str::extract_format_hints))
    /// so classification and inference read specifiers the same way.
    pub fn extract_format_hints(&self, format: &str) -> Vec<FormatHint> {
        extract_format_hints(format)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> StringClassifyEngine {
        StringClassifyEngine::with_default_patterns()
    }

    #[test]
    fn each_default_category_claims_its_shape_of_string() {
        let engine = classifier();
        assert_eq!(
            engine.classify("%s: %d hits"),
            StringClassification::FormatString
        );
        assert_eq!(
            engine.classify("Journal.txt"),
            StringClassification::FilePath
        );
        assert_eq!(
            engine.classify("C:\\game\\cfg.ini"),
            StringClassification::FilePath
        );
        assert_eq!(
            engine.classify("HKEY_LOCAL_MACHINE\\Software"),
            StringClassification::ResourceName
        );
        assert_eq!(
            engine.classify("Failed to open connection"),
            StringClassification::Error
        );
        assert_eq!(
            engine.classify("http://www.everquest.com"),
            StringClassification::Network
        );
        assert_eq!(
            engine.classify("Chat logging turned OFF."),
            StringClassification::DebugLog
        );
        assert_eq!(
            engine.classify("Press Enter to continue"),
            StringClassification::UserVisible
        );
        assert_eq!(
            engine.classify("LoggingOn"),
            StringClassification::InternalIdentifier
        );
        assert_eq!(
            engine.classify("~~~ ??? ~~~"),
            StringClassification::Generic
        );
    }

    #[test]
    fn a_string_matching_several_sets_lands_in_the_higher_priority_bucket() {
        let engine = classifier();
        // Matches the format-string, error, and file-path sets at once;
        // FormatString sits highest in the priority order.
        assert_eq!(
            engine.classify("Error: cannot open %s.dll"),
            StringClassification::FormatString
        );
        // Error outranks DebugLog; DebugLog outranks UserVisible.
        assert_eq!(
            engine.classify("warning: failed to log in"),
            StringClassification::Error
        );
        assert_eq!(
            engine.classify("debug: press OK to continue"),
            StringClassification::DebugLog
        );
        // A path with an error word still reads as a path: FilePath
        // outranks Error.
        assert_eq!(
            engine.classify("missing_file.cfg"),
            StringClassification::FilePath
        );
    }

    #[test]
    fn classification_is_deterministic_across_engines() {
        // Two standard classifiers are the same function of the string —
        // the priority lives in the engine, not in set order.
        let a = classifier();
        let b = classifier();
        for value in ["%d items", "C:\\a\\b.dll", "error occurred", "LoggingOn"] {
            assert_eq!(a.classify(value), b.classify(value), "{value}");
        }
    }

    #[test]
    fn a_classifier_with_no_patterns_reads_everything_generic() {
        let engine = StringClassifyEngine::new();
        assert_eq!(
            engine.classify("%s: %d hits"),
            StringClassification::Generic
        );
        assert_eq!(
            engine.classify("Journal.txt"),
            StringClassification::Generic
        );
    }

    #[test]
    fn fixture_pattern_sets_drive_classification_whole() {
        // Swapping every set whole reaches the scan: the fixture words
        // classify, and the standard patterns they replaced classify
        // nothing.
        let engine = StringClassifyEngine::with_patterns(CategoryPatterns {
            error: vec!["my_failure".to_string()],
            file_path: vec!["my_path".to_string()],
            ..CategoryPatterns::default()
        });
        assert_eq!(
            engine.classify("a my_failure happened"),
            StringClassification::Error
        );
        assert_eq!(
            engine.classify("open my_path here"),
            StringClassification::FilePath
        );
        assert_eq!(
            engine.classify("Failed to open connection"),
            StringClassification::Generic
        );
    }

    #[test]
    fn fixture_priority_lands_a_multi_match_in_the_higher_bucket() {
        // The fixture string matches both sets; the engine's fixed order
        // (Error before DebugLog) decides, not the field order.
        let engine = StringClassifyEngine::with_patterns(CategoryPatterns {
            debug_log: vec!["both".to_string()],
            error: vec!["both".to_string()],
            ..CategoryPatterns::default()
        });
        assert_eq!(engine.classify("both"), StringClassification::Error);
    }

    #[test]
    fn an_uncompilable_pattern_is_dropped_not_fatal() {
        let engine = StringClassifyEngine::with_patterns(CategoryPatterns {
            error: vec!["(unclosed".to_string(), "boom".to_string()],
            ..CategoryPatterns::default()
        });
        assert_eq!(engine.classify("boom"), StringClassification::Error);
    }

    #[test]
    fn every_category_carries_a_one_line_purpose() {
        let engine = classifier();
        let all = [
            StringClassification::FormatString,
            StringClassification::FilePath,
            StringClassification::ResourceName,
            StringClassification::Error,
            StringClassification::Network,
            StringClassification::DebugLog,
            StringClassification::UserVisible,
            StringClassification::InternalIdentifier,
            StringClassification::Generic,
        ];
        let mut purposes = Vec::new();
        for category in all {
            let purpose = engine.infer_purpose(category);
            assert!(!purpose.is_empty(), "{category} needs a purpose");
            assert!(!purpose.contains('\n'), "{category} purpose is one line");
            purposes.push(purpose);
        }
        purposes.sort();
        purposes.dedup();
        assert_eq!(
            purposes.len(),
            9,
            "each category reads with its own purpose"
        );
        assert_eq!(
            engine.infer_purpose(StringClassification::Error),
            "error message shown to the user"
        );
    }

    #[test]
    fn the_classifier_extracts_format_hints_with_specifiers_and_positions() {
        let engine = classifier();
        let hints = engine.extract_format_hints("%s: %d hits (%.2f%%)");
        let read: Vec<(&str, usize, &str)> = hints
            .iter()
            .map(|h| (h.specifier.as_str(), h.position, h.rust_type.as_str()))
            .collect();
        assert_eq!(
            read,
            vec![("%s", 0, "*const i8"), ("%d", 1, "i32"), ("%.2f", 2, "f32"),],
            "the literal %% takes no argument slot"
        );
    }
}
