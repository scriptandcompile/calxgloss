//! FFI bindings rendered from the persisted API detection result.
//!
//! [`render_ffi_bindings`] turns an [`ApiDetectionResult`] into one Rust
//! source string: every import the mapping database could **not** replace
//! with a crate gets an `extern "system"` declaration a reviewer can read
//! side by side with the JSON. The renderer is pure — data in, string
//! out — and deterministic: it walks the findings in scan order, groups
//! them by library when the entry knows one, and stamps no timestamp, so
//! two renders of the same document are byte-identical and a rescan
//! produces a reviewable diff, not churn.
//!
//! The rendering rules (ADR-0013's derived-rendered-artifact pattern,
//! applied to API findings):
//!
//! - **Only imports with no crate replacement are declared.** An
//!   identified import already names the crate standing in for it — the
//!   translation calls that crate, not the raw import — so it gets no
//!   declaration here.
//! - **Grouped by library when known.** Entries whose import record
//!   names a library render together under a `// {library}` comment, the
//!   groups in first-appearance order and the entries within a group in
//!   scan order; entries that know no library render without a header.
//! - **Sanitized identifiers, collision suffixes in render order.**
//!   Decorated and ordinal-only names (`?QueryInterface@IDataSource@@…`,
//!   `EXTERNAL:123`) become valid Rust identifiers (non-identifier
//!   characters collapse to `_`), a Rust keyword gains a trailing `_`,
//!   and a name already taken gains `_2`, `_3`, … in render order — so
//!   two same-named imports still get distinct, stable declarations.
//! - **No parameters, no return type.** The import table names the
//!   import and nothing else; inventing a signature would dress a guess
//!   up as evidence. The declaration says only that the symbol exists.
//! - **Nothing to declare renders nothing.** A result with no
//!   crate-less imports — an empty result included — renders an empty
//!   string: no header, no empty block, no noise in the diff.
//!
//! The output is a *derived artifact*: regenerated from the loaded
//! document beside the JSON it came from, and never read back — the JSON
//! stays the single source of truth.

use std::collections::HashSet;

use crate::types::{ApiDetectionResult, ApiFinding, ApiSignature};

/// Rust keywords and reserved words a sanitized identifier must not spell
/// verbatim; an import named one gets a trailing `_` instead.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "box", "break", "const", "continue", "crate", "do", "dyn", "else",
    "enum", "extern", "false", "final", "fn", "for", "if", "impl", "in", "let", "loop", "macro",
    "match", "mod", "move", "mut", "override", "pub", "ref", "return", "self", "Self", "static",
    "struct", "super", "trait", "true", "try", "type", "typeof", "union", "unsafe", "use",
    "virtual", "where", "while", "yield",
];

/// Render the detection result's crate-less imports as one Rust source
/// string.
///
/// Declarations appear in the document's own finding order — grouped by
/// library when the entry names one — and nothing volatile (timestamps,
/// counts) is written, so the same document always renders to the same
/// bytes. A document with no crate-less imports renders nothing: an
/// empty string, not a header-only file.
pub fn render_ffi_bindings(result: &ApiDetectionResult) -> String {
    // The imports to declare, in scan order: an import whose record
    // already names a Rust crate is replaced by that crate in
    // translation, so it needs no extern declaration here.
    let declared: Vec<&ApiSignature> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ApiFinding::Import(record) if record.rust_crate.is_none() => Some(record),
            _ => None,
        })
        .collect();
    if declared.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!(
        "// FFI bindings for {}, rendered by `calxgloss apidetect`.\n\
         // Derived artifact: regenerated from the API detection result on\n\
         // every scan — edit the result, never this file.\n\n\
         #![allow(dead_code, unused_imports)]\n",
        result.metadata.binary
    ));

    // Group by library in first-appearance order — the no-library group
    // (the ordinary unidentified import) renders without a header — and
    // keep each group's entries in scan order, so the same document
    // always renders the same blocks in the same order.
    let mut group_order: Vec<Option<&str>> = Vec::new();
    let mut groups: Vec<Vec<&ApiSignature>> = Vec::new();
    for record in &declared {
        let library = record.library.as_deref();
        if let Some(index) = group_order.iter().position(|key| *key == library) {
            groups[index].push(record);
        } else {
            group_order.push(library);
            groups.push(vec![record]);
        }
    }

    // Collision suffixes are handed out across the whole file, in render
    // order, so two same-named imports — in one library or across groups
    // — still get distinct, stable declarations.
    let mut taken: HashSet<String> = HashSet::new();
    for (library, members) in group_order.iter().zip(&groups) {
        out.push('\n');
        if let Some(library) = library {
            out.push_str(&format!("// {library}\n"));
        }
        out.push_str("extern \"system\" {\n");
        for record in members {
            let name = unique_name(&sanitize_import_name(&record.api), &mut taken);
            out.push_str(&format!("    fn {name}();\n"));
        }
        out.push_str("}\n");
    }
    out
}

/// Sanitize an import spelling into a valid Rust function identifier:
/// non-identifier characters become `_` (runs collapsed), a leading digit
/// is prefixed, a Rust keyword gains a trailing `_`, and a name left with
/// nothing falls back to `anonymous`. Case is preserved — import names
/// are spelled as the binary spells them, not renamed to a convention.
fn sanitize_import_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_end_matches('_').to_string();
    if out.is_empty() {
        return "anonymous".to_string();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("_{out}");
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        return format!("{out}_");
    }
    out
}

/// The first free name: two import tables can spell the same symbol
/// twice, so a collision gains `_2`, `_3`, … in render order —
/// deterministic, so re-renders never churn.
fn unique_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_string()) {
        return base.to_string();
    }
    let mut nth = 2;
    loop {
        let candidate = format!("{base}_{nth}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        nth += 1;
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PlatformDivergence, ScanMetadata};
    use calxgloss_types::Confidence;

    fn result_with(findings: Vec<ApiFinding>) -> ApiDetectionResult {
        let mut result = ApiDetectionResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        result
    }

    fn import(api: &str) -> ApiFinding {
        ApiFinding::Import(ApiSignature {
            api: api.into(),
            library: None,
            rust_crate: None,
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(0),
        })
    }

    fn mapped_import(api: &str, library: &str, rust_crate: &str) -> ApiFinding {
        ApiFinding::Import(ApiSignature {
            api: api.into(),
            library: Some(library.into()),
            rust_crate: Some(rust_crate.into()),
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(90),
        })
    }

    fn library_import(api: &str, library: &str) -> ApiFinding {
        ApiFinding::Import(ApiSignature {
            api: api.into(),
            library: Some(library.into()),
            rust_crate: None,
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(0),
        })
    }

    #[test]
    fn unidentified_imports_get_extern_declarations_and_identified_imports_are_excluded() {
        let result = result_with(vec![
            mapped_import("inflate", "zlib", "flate2"),
            import("VendorSpecialFunction"),
            mapped_import("CreateFileA", "Win32", "windows / std::fs"),
        ]);

        let rendered = render_ffi_bindings(&result);

        assert!(
            rendered.contains("    fn VendorSpecialFunction();\n"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("inflate"),
            "a crate-replaced import gets no declaration: {rendered}"
        );
        assert!(
            !rendered.contains("CreateFileA"),
            "a crate-replaced import gets no declaration: {rendered}"
        );
        assert!(rendered.contains("extern \"system\" {"), "{rendered}");
    }

    #[test]
    fn non_import_findings_get_no_declaration() {
        // Divergence and COM claims name shapes, not linkable symbols,
        // and usages repeat identified imports — only crate-less import
        // entries stand on the declaration list.
        let mut result = result_with(vec![import("VendorSpecialFunction")]);
        result
            .findings
            .push(ApiFinding::PlatformDivergence(PlatformDivergence {
                families: vec!["Win32Core".into(), "POSIX".into()],
                evidence: "CreateFileA (Win32Core), fopen (POSIX)".into(),
                confidence: Confidence::new(70),
            }));

        let rendered = render_ffi_bindings(&result);

        assert_eq!(rendered.matches("fn ").count(), 1, "{rendered}");
        assert!(
            rendered.contains("fn VendorSpecialFunction();"),
            "{rendered}"
        );
    }

    #[test]
    fn decorated_and_ordinal_names_are_sanitized_to_valid_identifiers() {
        let result = result_with(vec![
            import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
            import("EXTERNAL:123"),
            import("operator new"),
            import("try"),
        ]);

        let rendered = render_ffi_bindings(&result);

        assert!(
            rendered.contains("fn _QueryInterface_IDataSource_UEAAJPEAXPEAPEAX_Z();"),
            "{rendered}"
        );
        assert!(rendered.contains("fn EXTERNAL_123();"), "{rendered}");
        assert!(rendered.contains("fn operator_new();"), "{rendered}");
        assert!(rendered.contains("fn try_();"), "{rendered}");
    }

    #[test]
    fn colliding_names_gain_suffixes_in_render_order() {
        let result = result_with(vec![
            import("VendorSpecialFunction"),
            import("VendorSpecialFunction"),
            import("vendor_special_function"),
        ]);

        let rendered = render_ffi_bindings(&result);

        assert!(
            rendered.contains("fn VendorSpecialFunction();"),
            "{rendered}"
        );
        assert!(
            rendered.contains("fn VendorSpecialFunction_2();"),
            "{rendered}"
        );
        assert!(
            rendered.contains("fn vendor_special_function();"),
            "{rendered}"
        );
    }

    #[test]
    fn entries_are_grouped_by_library_when_known() {
        // Library-known entries render under a `// {library}` comment in
        // first-appearance order, entries within a group in scan order;
        // the library-less entries render without a header.
        let result = result_with(vec![
            import("VendorSpecialFunction"),
            library_import("Engine_LoadAsset", "CustomEngine"),
            library_import("Engine_Tick", "CustomEngine"),
            import("AnotherVendorFunction"),
            library_import("Helper_Init", "HelperLib"),
        ]);

        let rendered = render_ffi_bindings(&result);

        let engine_at = rendered
            .find("// CustomEngine\nextern \"system\" {\n    fn Engine_LoadAsset();\n    fn Engine_Tick();\n}")
            .unwrap_or_else(|| panic!("the CustomEngine group renders together: {rendered}"));
        let helper_at = rendered
            .find("// HelperLib\nextern \"system\" {\n    fn Helper_Init();\n}")
            .unwrap_or_else(|| {
                panic!("the HelperLib group renders under its own header: {rendered}")
            });
        let vendor_at = rendered
            .find("extern \"system\" {\n    fn VendorSpecialFunction();\n    fn AnotherVendorFunction();\n}")
            .unwrap_or_else(|| panic!("the library-less group keeps scan order: {rendered}"));
        assert!(
            vendor_at < engine_at && engine_at < helper_at,
            "groups appear in first-appearance order: {rendered}"
        );
    }

    #[test]
    fn two_renders_of_the_same_result_are_byte_identical() {
        let result = result_with(vec![
            mapped_import("inflate", "zlib", "flate2"),
            import("VendorSpecialFunction"),
            import("EXTERNAL:123"),
            library_import("Engine_LoadAsset", "CustomEngine"),
        ]);

        assert_eq!(render_ffi_bindings(&result), render_ffi_bindings(&result));
    }

    #[test]
    fn the_header_names_only_the_binary_never_the_scan_time() {
        let result = result_with(vec![import("VendorSpecialFunction")]);

        let rendered = render_ffi_bindings(&result);

        assert!(
            rendered.starts_with(
                "// FFI bindings for eqmain.dll, rendered by `calxgloss apidetect`.\n"
            ),
            "{rendered}"
        );
        let header = rendered.split("extern").next().unwrap_or_default();
        assert!(
            !header.chars().any(|c| c.is_ascii_digit()),
            "the header names no timestamp: {header}"
        );
    }

    #[test]
    fn an_empty_result_renders_nothing() {
        // The empty-input behavior pinned by test: nothing to declare is
        // an empty string, not a header-only file — a rescan of a
        // fully-identified binary never churns the artifact.
        assert_eq!(render_ffi_bindings(&result_with(Vec::new())), "");
    }

    #[test]
    fn a_result_of_only_identified_imports_renders_nothing() {
        let result = result_with(vec![
            mapped_import("inflate", "zlib", "flate2"),
            mapped_import("CreateFileA", "Win32", "windows / std::fs"),
        ]);

        assert_eq!(render_ffi_bindings(&result), "");
    }

    #[test]
    fn sanitizers_refuse_invalid_identifiers() {
        assert_eq!(
            sanitize_import_name("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
            "_QueryInterface_IDataSource_UEAAJPEAXPEAPEAX_Z"
        );
        assert_eq!(sanitize_import_name("EXTERNAL:123"), "EXTERNAL_123");
        assert_eq!(sanitize_import_name("operator new"), "operator_new");
        assert_eq!(sanitize_import_name("2bytes"), "_2bytes");
        assert_eq!(sanitize_import_name("type"), "type_");
        assert_eq!(sanitize_import_name("@@@@"), "anonymous");
    }

    #[test]
    fn a_small_result_renders_the_whole_file_verbatim() {
        // The golden render: header, the library-less block, and a
        // library-grouped block with a collision suffix — pinned byte
        // for byte so any formatting change shows up as a diff.
        let result = result_with(vec![
            mapped_import("inflate", "zlib", "flate2"),
            import("VendorSpecialFunction"),
            import("EXTERNAL:123"),
            library_import("Engine_LoadAsset", "CustomEngine"),
            library_import("Engine_LoadAsset", "CustomEngine"),
        ]);

        let expected = "\
// FFI bindings for eqmain.dll, rendered by `calxgloss apidetect`.
// Derived artifact: regenerated from the API detection result on
// every scan — edit the result, never this file.

#![allow(dead_code, unused_imports)]

extern \"system\" {
    fn VendorSpecialFunction();
    fn EXTERNAL_123();
}

// CustomEngine
extern \"system\" {
    fn Engine_LoadAsset();
    fn Engine_LoadAsset_2();
}
";

        assert_eq!(render_ffi_bindings(&result), expected);
    }
}
