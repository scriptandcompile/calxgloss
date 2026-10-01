//! Hallucination detector for LLM-generated Rust code.
//!
//! This module provides [`HallucinationDetector`] which scans the LLM's
//! generated Rust source code for function and API calls that are not present
//! in Ghidra's symbol table or the known Windows API catalogue.  When a
//! hallucination is detected the caller is notified so it can branch from the
//! last known good commit and prompt the LLM with Ghidra's actual symbols as
//! ground truth.
//!
//! # How it works
//!
//! The detector maintains a set of *known-good* symbols, built from three
//! sources:
//!
//! 1. **Ghidra function names** — every function Ghidra has catalogued in the
//!    open program.
//! 2. **Ghidra imports** — every symbol the program imports from external DLLs.
//! 3. **Windows API catalogue** — the full PAL mapping table (every Windows API
//!    the harness knows about).
//!
//! When the LLM returns generated Rust code, the detector extracts every
//! identifier that looks like a function call (a word followed immediately by
//! `(`) and checks each candidate against the known-good set.  Names that are
//! not found are reported as hallucinations, along with the closest valid
//! match from the catalogue when available.
//!
//! # Example
//!
//! ```
//! use calxgloss_llm::hallucination::HallucinationDetector;
//!
//! let detector = HallucinationDetector::new(
//!     vec!["CreateFileA".to_string(), "WriteFile".to_string(), "DrawSprite".to_string()],
//!     vec!["CreateFileA".to_string(), "WriteFile".to_string(), "ReadFile".to_string()],
//! );
//!
//! // The LLM hallucinated `CreateDXTexture` — it does not exist.
//! let results = detector.detect(
//!     r#"fn draw() {
//!     let tex = CreateDXTexture(100, 100);
//!     DrawSprite(tex);
//! }"#,
//! );
//! assert_eq!(results.len(), 1);
//! assert_eq!(results[0].name, "CreateDXTexture");
//! ```

use std::collections::HashSet;

// ============================================================
// Public types
// ============================================================

/// A single hallucinated call detected in LLM-generated code.
///
/// Contains the suspicious identifier, the exact code context where it was
/// found, and optionally the closest known-good match from the detector's
/// symbol catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HallucinatedCall {
    /// The identifier that the LLM used as a function call but which is not
    /// present in any known-good symbol set.
    pub name: String,

    /// The line of generated code that contains the hallucination, provided
    /// for the reviewer to quickly understand the context.
    pub code_context: String,

    /// A suggested replacement from the known-good catalogue, if the detector
    /// found a similar name.  `None` when no close match exists.
    pub closest_match: Option<String>,
}

/// A detector that identifies non-existent API references and hallucinated
/// function calls in LLM-generated Rust code.
///
/// The detector is created with a list of known-good symbols (Ghidra function
/// names, imports, and Windows APIs).  When [`Self::detect`] is called with
/// the LLM's generated code, it returns a list of hallucinated calls.
///
/// # Construction
///
/// ```
/// use calxgloss_llm::hallucination::HallucinationDetector;
///
/// // Typically built from Ghidra's symbol tables.
/// let detector = HallucinationDetector::new(
///     vec!["DrawSprite".to_string(), "FUN_18008ed50".to_string()],
///     vec!["CreateFileA".to_string(), "WriteFile".to_string()],
/// );
/// ```
#[derive(Debug, Clone)]
pub struct HallucinationDetector {
    /// Function names from Ghidra (exports, user-defined functions).
    functions: HashSet<String>,

    /// Import names from Ghidra (DLL imports).
    /// Stored separately for potential close-match filtering by category.
    #[allow(dead_code)]
    imports: HashSet<String>,

    /// Combined set of all known-good symbols (functions + imports).
    all_valid: HashSet<String>,
}

// ============================================================
// Implementation
// ============================================================

impl HallucinationDetector {
    /// Create a new detector from the provided symbol sources.
    ///
    /// # Arguments
    ///
    /// * `functions` — Ghidra function names (exports, user-defined functions
    ///   like `DrawSprite` or `FUN_18008ed50`).
    /// * `imports` — Import names from Ghidra (DLL imports like
    ///   `CreateFileA`, `WriteFile`).
    ///
    /// The detector builds a combined set of valid symbols and also uses the
    /// import set to provide close-match suggestions.
    pub fn new(functions: Vec<String>, imports: Vec<String>) -> Self {
        let all_valid: HashSet<String> = functions
            .iter()
            .chain(imports.iter())
            .cloned()
            .collect();

        Self {
            functions: functions.into_iter().collect(),
            imports: imports.into_iter().collect(),
            all_valid,
        }
    }

    /// Create a new detector that accepts *only* the given symbols.
    ///
    /// Use this when you have a pre-built set of valid symbols (e.g., from a
    /// catalogued Windows API list) rather than Ghidra symbol tables.
    pub fn from_symbols(symbols: Vec<String>) -> Self {
        let all_valid: HashSet<String> = symbols.clone().into_iter().collect();
        Self {
            functions: symbols.clone().into_iter().collect(),
            imports: all_valid.clone(),
            all_valid,
        }
    }

    /// Scan the LLM-generated code and return a list of hallucinated calls.
    ///
    /// This is the primary detection method called after every LLM response.
    /// It extracts every identifier that looks like a function call, checks
    /// it against the known-good symbol set, and reports mismatches.
    ///
    /// # Arguments
    ///
    /// * `generated_code` — The Rust source code generated by the LLM.
    ///
    /// # Returns
    ///
    /// A vector of [`HallucinatedCall`] instances, one per hallucinated
    /// function/API reference found in the code.  An empty vector means no
    /// hallucinations were detected.
    pub fn detect(&self, generated_code: &str) -> Vec<HallucinatedCall> {
        let mut hallucinations = Vec::new();
        let mut seen = HashSet::new();

        // Split into lines and scan each one for function-call-like patterns.
        for line in generated_code.lines() {
            // Skip comment lines (both `//` and `/* */` style).
            let trimmed = line.trim();
            if trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with("*")
            {
                continue;
            }

            // Extract all `IDENTIFIER(...)` patterns from this line.
            let candidates = extract_call_candidates(line);

            for (name, code_line) in candidates {
                // Skip duplicates within the same response.
                if !seen.insert(name.clone()) {
                    continue;
                }

                // Skip function definitions (e.g. `fn draw() {`).
                if Self::is_function_def(line, &name) {
                    continue;
                }

                // Skip false positives.
                if is_false_positive(&name) {
                    continue;
                }

                // Check against known-good symbols.
                if !self.is_valid(&name) {
                    let closest = self.find_closest_match(&name);
                    hallucinations.push(HallucinatedCall {
                        name: name.clone(),
                        code_context: code_line.trim().to_string(),
                        closest_match: closest,
                    });
                }
            }
        }

        hallucinations
    }

    /// Check whether a line defines a function with the given name
    /// (e.g. `fn draw() {` or `fn foo<T>() -> T`).
    fn is_function_def(line: &str, name: &str) -> bool {
        let line_trimmed = line.trim();
        let pattern = format!("fn {name}");
        if let Some(pos) = line_trimmed.find(&pattern) {
            let after = pos + pattern.len();
            if after >= line_trimmed.len() {
                return true;
            }
            let next_char = line_trimmed[after..].chars().next();
            // The name must be followed by a non-identifier character.
            next_char.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
        } else {
            false
        }
    }

    /// Check whether an identifier is a known-good symbol.
    pub fn is_valid(&self, name: &str) -> bool {
        self.all_valid.contains(name)
    }

    /// Find the closest known-good match for a name using case-insensitive
    /// prefix matching.
    ///
    /// The algorithm iterates through all known-good symbols and finds the one
    /// with the longest shared prefix (case-insensitive) with the given name.
    /// If no shared prefix exists, the first known-good function name is
    /// returned as a fallback.
    pub fn find_closest_match(&self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        let mut best_match: Option<(usize, String)> = None;
        for sym in &self.all_valid {
            let sym_lower = sym.to_lowercase();
            // Count the actual shared prefix length.
            let shared = name_lower
                .chars()
                .zip(sym_lower.chars())
                .take_while(|(a, b)| a == b)
                .count();
            if shared >= 4
                && best_match.as_ref().is_none_or(|(best_len, _)| shared > *best_len)
            {
                best_match = Some((shared, sym.clone()));
            }
        }

        if let Some((_len, sym)) = best_match {
            return Some(sym);
        }

        // Fallback: return the first known-good function name so the user
        // at least sees what the valid options look like.
        self.functions.iter().next().cloned()
    }
}

// ============================================================
// Identifier extraction
// ============================================================

/// Extract all `IDENTIFIER(...)` patterns from a line of Rust code.
///
/// Returns a vector of `(name, code_context)` tuples, one for each candidate
/// function call found in the line.  The `code_context` is the full line for
/// review purposes.
///
/// This function is intentionally simple: it looks for an alphanumeric
/// identifier (possibly with underscores) immediately followed by `(`, and
/// handles type parameters like `<u32>` that may appear between the name and
/// the parenthesis.
fn extract_call_candidates(line: &str) -> Vec<(String, String)> {
    let mut candidates = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Find the start of an identifier (alphanumeric or underscore).
        if !chars[i].is_ascii_alphanumeric() && chars[i] != '_' {
            i += 1;
            continue;
        }

        let start = i;
        while i < len
            && (chars[i].is_ascii_alphanumeric() || chars[i] == '_')
        {
            i += 1;
        }
        let ident_start = start;
        let ident_end = i;

        // Skip whitespace between the identifier and the opening paren.
        let mut after_name = i;
        while after_name < len && chars[after_name].is_ascii_whitespace() {
            after_name += 1;
        }

        // Handle type parameters: `foo::<u32>(` or `foo::<T, E>(`.
        // Skip from `::` to `(`.
        if after_name < len && after_name + 2 < len
            && chars[after_name] == ':'
            && chars[after_name + 1] == ':'
            && after_name + 3 < len
            && chars[after_name + 3] == '<'
        {
            // Find the matching `>`.
            let mut depth = 1;
            let mut j = after_name + 4;
            while j < len && depth > 0 {
                if chars[j] == '<' {
                    depth += 1;
                } else if chars[j] == '>' {
                    depth -= 1;
                }
                j += 1;
            }
            after_name = j;
            // Skip whitespace after `>`.
            while after_name < len && chars[after_name].is_ascii_whitespace() {
                after_name += 1;
            }
        }

        // Handle method calls: `Type::method(` — also emit `Type` as a candidate.
        if after_name < len && after_name + 2 < len
            && (chars[after_name] == ':'
                && chars[after_name + 1] == ':'
                && chars[after_name + 2].is_ascii_alphabetic()
                || chars[after_name] == ':'
                    && chars[after_name + 1] == ':'
                    && after_name + 3 < len
                    && chars[after_name + 3] == '<')
        {
            // Find the method name after `::` (or after `>::`).
            let mut method_start = after_name + 2;
            // Skip generic params if present.
            if method_start < len && chars[method_start] == '<' {
                let mut depth = 1;
                method_start += 1;
                while method_start < len && depth > 0 {
                    if chars[method_start] == '<' {
                        depth += 1;
                    } else if chars[method_start] == '>' {
                        depth -= 1;
                    }
                    method_start += 1;
                }
            }
            // Skip whitespace.
            while method_start < len && chars[method_start].is_ascii_whitespace() {
                method_start += 1;
            }
            // Read the method name.
            let m_start = method_start;
            while method_start < len
                && (chars[method_start].is_ascii_alphanumeric()
                    || chars[method_start] == '_')
            {
                method_start += 1;
            }
            if method_start > m_start {
                // Check the method is followed by `(` (possibly with whitespace).
                let mut m_after = method_start;
                while m_after < len && chars[m_after].is_ascii_whitespace() {
                    m_after += 1;
                }
                if m_after < len && chars[m_after] == '(' {
                    // Emit the type name as a candidate too.
                    let type_name =
                        chars[ident_start..ident_end].iter().collect::<String>();
                    let mut paren_depth = 1;
                    let mut j = m_after + 1;
                    while j < len && paren_depth > 0 {
                        if chars[j] == '(' {
                            paren_depth += 1;
                        } else if chars[j] == ')' {
                            paren_depth -= 1;
                        }
                        j += 1;
                    }
                    let code_context: String =
                        chars[ident_start..j.min(len)].iter().collect();
                    candidates.push((type_name, code_context));
                    // Advance past `::method(...)` so `method` isn't
                    // extracted as a separate identifier later.
                    after_name = j.min(len);
                }
            }
        }

        // Check if followed by `(` — this is a potential function call.
        if after_name < len && chars[after_name] == '(' {
            let name = chars[ident_start..ident_end].iter().collect::<String>();
            // Collect the rest of the line as code context (up to the closing paren).
            let mut paren_depth = 1;
            let mut j = after_name + 1;
            while j < len && paren_depth > 0 {
                if chars[j] == '(' {
                    paren_depth += 1;
                } else if chars[j] == ')' {
                    paren_depth -= 1;
                }
                j += 1;
            }
            let code_context: String = chars[ident_start..j.min(len)].iter().collect();
            candidates.push((name, code_context));
        }
    }

    candidates
}

// ============================================================
// False positive filtering
// ============================================================

/// Rust language keywords that can appear before `(` in generated code.
///
/// These are filtered out because they are control-flow constructs, not
/// actual function calls.
const RUST_KEYWORDS: &[&str] = &[
    // Flow control.
    "if", "else", "while", "loop", "for", "match",
    // Blocks and closures.
    "move", "async", "await",
    // Type-related.
    "type", "impl", "trait", "mod", "use", "pub",
    // Declarations.
    "fn", "struct", "enum", "union", "const", "static",
    // Lifetime and generics.
    "where", "dyn", " Self ", "super", "crate",
    // Literals and expressions.
    "true", "false", "self", "Self",
    // Pattern matching.
    "ref", "mut", "let",
    // Operators and macros.
    "return", "break", "continue",
    // Module system.
    "unsafe", "extern", "crate",
];

/// Type constructor names that are common false positives.
///
/// These are standard Rust types whose constructors (`Some()`, `Ok()`, etc.)
/// look like function calls but are not hallucinated references.
const TYPE_CONSTRUCTORS: &[&str] = &[
    "some", "none", "ok", "err",
    "result", "option", "vec", "string", "str",
    "boxed", "box", "rc", "arc", "cell", "refcell",
    "hashmap", "hashset", "btreemap", "btree",
    "io", "mem", "ptr", "sync", "thread",
    "println", "print", "format", "panic",
    // Common static-method / constructor patterns.
    "new", "default", "from", "into", "try_from", "try_into",
    "unwrap", "expect", "clone", "copy", "as_ref", "as_mut",
    "len", "is_empty", "iter", "into_iter",
    // Primitive type names that can appear in casts / type ascriptions.
    "i32", "i64", "i16", "i8", "u32", "u64", "u16", "u8",
    "f32", "f64", "bool", "char", "usize", "isize",
];

/// Check whether an identifier is a known false positive.
fn is_false_positive(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Rust keywords.
    if RUST_KEYWORDS.contains(&lower.as_str()) {
        return true;
    }

    // Type constructors and standard library patterns.
    if TYPE_CONSTRUCTORS.contains(&lower.as_str()) {
        return true;
    }

    // Single uppercase letters (Rust generic type params: T, U, E, K, V, etc.)
    // Two uppercase letters that look like type abbreviations (IO, ST, etc.)
    let upper = name.chars().all(|c| c.is_ascii_uppercase());
    let is_single_alpha = name.chars().all(|c| c.is_ascii_alphabetic());
    if name.len() <= 2 && upper && is_single_alpha {
        return true;
    }

    // Three uppercase letters that could be type abbreviations, unless they
    // look like a real identifier (contain digits or a common suffix like "er", "or").
    if name.len() == 3
        && upper
        && is_single_alpha
        && !name.ends_with("er")
        && !name.ends_with("or")
    {
        return true;
    }

    // Macro invocation marker.
    if name == "!" {
        return true;
    }

    false
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================
    // Construction
    // =========================================================

    #[test]
    fn test_detector_creation() {
        let detector = HallucinationDetector::new(
            vec!["DrawSprite".to_string(), "UpdatePosition".to_string()],
            vec!["CreateFileA".to_string(), "WriteFile".to_string()],
        );
        assert!(detector.is_valid("DrawSprite"));
        assert!(detector.is_valid("CreateFileA"));
        assert!(detector.is_valid("UpdatePosition"));
        assert!(detector.is_valid("WriteFile")); // imports are merged into all_valid
    }

    #[test]
    fn test_detector_from_symbols() {
        let detector = HallucinationDetector::from_symbols(vec![
            "CreateFileA".to_string(),
            "WriteFile".to_string(),
        ]);
        assert!(detector.is_valid("CreateFileA"));
        assert!(detector.is_valid("WriteFile"));
        assert!(!detector.is_valid("NonExistent"));
    }

    // =========================================================
    // No hallucinations
    // =========================================================

    #[test]
    fn test_detect_no_hallucinations() {
        let detector = HallucinationDetector::new(
            vec!["DrawSprite".to_string()],
            vec!["CreateFileA".to_string()],
        );
        let code = r#"fn draw() {
            CreateFileA("test.txt", 0, 0, None, 0, 0, None);
            DrawSprite(x, y);
        }"#;
        let results = detector.detect(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_simple_hallucination() {
        let detector = HallucinationDetector::new(
            vec!["DrawSprite".to_string()],
            vec!["CreateFileA".to_string()],
        );
        let code = r#"fn draw() {
            CreateDXTexture(100, 100);
        }"#;
        let results = detector.detect(code);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "CreateDXTexture");
    }

    #[test]
    fn test_detect_multiple_hallucinations() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() {
            FakeFunction1();
            FakeFunction2();
            DrawSprite(x, y);
        }"#;
        let results = detector.detect(code);
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"FakeFunction1"));
        assert!(names.contains(&"FakeFunction2"));
    }

    #[test]
    fn test_detect_deduplication() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() {
            FakeFunc();
            FakeFunc();
            FakeFunc();
        }"#;
        let results = detector.detect(code);
        assert_eq!(results.len(), 1);
    }

    // =========================================================
    // False positive filtering
    // =========================================================

    #[test]
    fn test_skips_rust_keywords() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() {
            if (x > 0) {
                while (running) {
                    match (value) {
                        Some(v) => {}
                        None => {}
                    }
                }
            }
        }"#;
        let results = detector.detect(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_skips_type_constructors() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() {
            let x = Some(42);
            let y = Ok(());
            let z = Err("fail");
            let v = Vec::new();
            let s = String::new();
            let map = HashMap::new();
        }"#;
        let results = detector.detect(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_skips_comments() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() {
            // FakeFunction() — this is a comment
            /* AnotherFake() */
            /*
             * MultiLineFake()
             */
            DrawSprite(x, y);
        }"#;
        let results = detector.detect(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_skips_type_parameters() {
        let detector = HallucinationDetector::new(vec!["DrawSprite".to_string()], vec![]);
        let code = r#"fn draw() -> Result<(), E> {
            let x: Option<T> = None;
            Box::new(())
        }"#;
        let results = detector.detect(code);
        assert!(results.is_empty());
    }

    // =========================================================
    // Closest match
    // =========================================================

    #[test]
    fn test_closest_match_prefix() {
        let detector = HallucinationDetector::new(
            vec!["DrawSprite".to_string()],
            vec!["CreateFileA".to_string(), "CreateEvent".to_string()],
        );
        let closest = detector.find_closest_match("CreateDXTexture");
        // Should find a Create* match due to prefix sharing.
        assert!(closest.is_some());
        assert!(closest.as_ref().unwrap().starts_with("Create"));
    }

    #[test]
    fn test_closest_match_no_prefix() {
        let detector = HallucinationDetector::new(
            vec!["DrawSprite".to_string()],
            vec!["CreateFileA".to_string()],
        );
        let closest = detector.find_closest_match("QuantumBooster");
        // No prefix match, should fall back to first function.
        assert_eq!(closest, Some("DrawSprite".to_string()));
    }

    // =========================================================
    // Identifier extraction
    // =========================================================

    #[test]
    fn test_extract_call_candidates_basic() {
        let line = "    let x = foo(1, 2);";
        let candidates = extract_call_candidates(line);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "foo");
    }

    #[test]
    fn test_extract_call_candidates_with_generics() {
        let line = "    let x = Result::<u32, E>::Ok(42);";
        let candidates = extract_call_candidates(line);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "Ok");
    }

    #[test]
    fn test_extract_call_candidates_multiple() {
        let line = "    foo(bar(1), baz(2));";
        let candidates = extract_call_candidates(line);
        assert_eq!(candidates.len(), 3);
        let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
    }

    #[test]
    fn test_extract_call_candidates_skips_type_params() {
        let line = "    let x: HashMap<String, i32> = HashMap::new();";
        let candidates = extract_call_candidates(line);
        // `HashMap::new` is extracted, but `String` and `i32` inside angle brackets
        // should not be, since they're not followed by `(`.
        let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"HashMap"));
    }

    #[test]
    fn test_extract_call_candidates_empty_line() {
        let line = "";
        let candidates = extract_call_candidates(line);
        assert!(candidates.is_empty());
    }

    // =========================================================
    // False positive filtering
    // =========================================================

    #[test]
    fn test_false_positive_rust_keywords() {
        assert!(is_false_positive("if"));
        assert!(is_false_positive("while"));
        assert!(is_false_positive("match"));
        assert!(is_false_positive("fn"));
        assert!(is_false_positive("struct"));
        assert!(is_false_positive("unsafe"));
    }

    #[test]
    fn test_false_positive_type_constructors() {
        assert!(is_false_positive("Some"));
        assert!(is_false_positive("Ok"));
        assert!(is_false_positive("Err"));
        assert!(is_false_positive("None"));
        assert!(is_false_positive("Vec"));
        assert!(is_false_positive("String"));
        assert!(is_false_positive("println"));
    }

    #[test]
    fn test_false_positive_type_params() {
        assert!(is_false_positive("T"));
        assert!(is_false_positive("E"));
        assert!(is_false_positive("K"));
        assert!(is_false_positive("V"));
        assert!(is_false_positive("i32"));
    }

    #[test]
    fn test_not_false_positive() {
        assert!(!is_false_positive("CreateFileA"));
        assert!(!is_false_positive("DrawSprite"));
        assert!(!is_false_positive("FakeFunction"));
        assert!(!is_false_positive("foo"));
    }
}
