//! Helper functions for sanitizing identifiers and crate names.

/// Sanitize a string for use as a Cargo crate name.
pub fn sanitize_crate_name(name: &str) -> String {
    name.replace(|c: char| !c.is_alphanumeric() && c != '-', "_")
}

/// Sanitize a string for use as a Rust identifier.
pub fn sanitize_identifier(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.chars().next().is_none_or(|c| c.is_ascii_digit()) {
        format!("_{}", sanitized)
    } else {
        sanitized
    }
}
