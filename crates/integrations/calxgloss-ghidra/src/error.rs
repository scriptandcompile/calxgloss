//! Recognising failure in GhidraMCP's responses.
//!
//! The server reports most failures as `200 OK` with an explanation in the
//! body — either a plain-text line or, on the 6.x bridge, a JSON object like
//! `{"error":"No function found for 1"}` — so a client that trusts the status
//! code silently accepts error text as data. Every response therefore goes
//! through [`classify`] before its content is parsed.
//!
//! The recognised messages are the ones the server actually emits, taken from
//! the Ghidra plugin's string constants. A body that is not recognised is
//! treated as content, not an error: a newly worded message should surface as
//! odd data for a human to read rather than as a spurious failure.

/// Body prefixes the server sends instead of a result.
///
/// Matched case-insensitively against the trimmed body's start, so a message
/// that gains detail later still matches.
const SERVER_ERROR_PREFIXES: &[&str] = &[
    // Missing or unusable parameters.
    "Address is required",
    "Function name is required",
    "Function address is required",
    "Function prototype is required",
    "Search term is required",
    "Program name is required",
    "Error decoding URL parameter",
    // Nothing at the requested location.
    "Function not found",
    "No function found at address",
    "No function found at or containing address",
    "No function found for",
    "No function at current location",
    "No program found",
    "No functions matching",
    "No context found for request",
    // The operation itself failed.
    "Error decompiling function",
    "Error disassembling function",
    "Error getting function",
    "Error getting function references",
    "Error getting references from address",
    "Error getting references to address",
    "Error applying function signature",
    "Error renaming function",
    "Error setting function prototype",
    "Error setting variable type",
    "Base type not found",
];

/// What a response turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification<'a> {
    /// The body is a result.
    Content,
    /// The body is the server explaining a failure.
    Failure(&'a str),
    /// The body is the server explaining a failure, prefixed by a status code.
    /// This is the shape the MCP bridge produces when it forwards an error.
    FailureWithStatus(u16, &'a str),
    /// The body could not be understood at all.
    Unrecognised(&'a str),
}

/// Decide whether a response body is a result or an error message.
///
/// This is the crate's load-bearing assumption about the server: the status code
/// is not enough, and a body must be inspected before it is trusted.
pub fn classify(body: &str) -> Classification<'_> {
    let trimmed = body.trim();

    // A 6.x-bridge failure: `{"error":"No function found for 1"}`, sent with
    // status 200 like everything else.
    if let Some(message) = json_error_message(trimmed) {
        return Classification::Failure(message);
    }

    // A bridge-shaped failure: `Error 404: No context found for request`.
    if let Some(rest) = trimmed.strip_prefix("Error ")
        && let Some((code, message)) = rest.split_once(':')
        && let Ok(status) = code.trim().parse::<u16>()
    {
        return Classification::FailureWithStatus(status, message.trim());
    }

    // A transport-level failure the bridge could not even attempt.
    if trimmed.starts_with("Request failed:") {
        return Classification::Failure(trimmed);
    }

    for prefix in SERVER_ERROR_PREFIXES {
        if starts_with_ignore_ascii_case(trimmed, prefix) {
            return Classification::Failure(trimmed);
        }
    }

    // An empty body is not a result. Treating it as one would let a silently
    // blank response read as "no such function", which is a different claim.
    if trimmed.is_empty() {
        return Classification::Unrecognised(trimmed);
    }

    Classification::Content
}

/// Whether `text` starts with `prefix`, ignoring ASCII case.
fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Extract the message from a JSON error body, if the body is one.
///
/// The 6.x bridge answers failures with `{"error":"..."}`. The scan is textual
/// rather than a full parse because the result borrows from the body, and an
/// object that merely *contains* an `error` key deeper inside is content, not a
/// failure — only a top-level `error` string counts.
fn json_error_message(body: &str) -> Option<&str> {
    let rest = body.strip_prefix('{')?.trim_start();
    let rest = rest.strip_prefix("\"error\"")?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    // Read to the closing quote, stepping over `\"` escapes so an escaped
    // quote inside the message cannot end it early.
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(&rest[..i]),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognises_real_server_messages() {
        for body in [
            "Address is required",
            "Function not found",
            "No function found at or containing address 0xdeadbeef",
            "No functions matching 'zzz'",
            "Error decompiling function: boom",
            "Error getting references to address: boom",
        ] {
            assert!(
                matches!(classify(body), Classification::Failure(_)),
                "should be a failure: {body:?}"
            );
        }
    }

    #[test]
    fn test_recognises_bridge_shaped_failures() {
        assert_eq!(
            classify("Error 404: <h1>404 Not Found</h1>No context found for request"),
            Classification::FailureWithStatus(
                404,
                "<h1>404 Not Found</h1>No context found for request"
            )
        );
        assert!(matches!(
            classify("Request failed: Connection refused"),
            Classification::Failure(_)
        ));
    }

    #[test]
    fn test_recognises_json_shaped_failures() {
        // The 6.x bridge answers failures as `200 OK` with `{"error": "..."}`.
        assert_eq!(
            classify("{\"error\":\"No function found for 1\"}"),
            Classification::Failure("No function found for 1")
        );
        assert_eq!(
            classify(" {\"error\" : \"Search term is required\"} "),
            Classification::Failure("Search term is required")
        );
        // An escaped quote must not end the message early.
        assert_eq!(
            classify("{\"error\":\"bad \\\"name\\\"\"}"),
            Classification::Failure("bad \\\"name\\\"")
        );
    }

    #[test]
    fn test_json_results_are_not_mistaken_for_failures() {
        // These are real 6.x-bridge result bodies; the `error` scan must only
        // fire on a top-level `error` key.
        for body in [
            "{\"function_count\":4587,\"program\":\"eqmain.dll\"}",
            "{\"address\":\"1800e2110\",\"program\":\"/eqmain.dll\"}",
            "{\"success\":true,\"switched_to\":\"eqmain.dll\"}",
            "[{\"name\":\"Ordinal_7\",\"address\":\"EXTERNAL:00000001\"}]",
        ] {
            assert_eq!(
                classify(body),
                Classification::Content,
                "should be content: {body:?}"
            );
        }
    }

    #[test]
    fn test_real_content_is_not_mistaken_for_failure() {
        // Each of these is a real response body; misreading any of them as an
        // error would make the client report failures for a working server.
        for body in [
            "FUN_18008ed50 @ 18008ed50",
            "FUN_180001090 at 180001090",
            "longlong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return 0;\n}",
            "dll_main -> 18000c690",
            "From 18000a3be in FUN_18000a0d0 [UNCONDITIONAL_CALL]",
            ".text: 180001000 - 1801261ff",
            "180127cd8: \"Everquest\"",
            "Function: FUN_18008ed50 at 18008ed50",
            "18008ed50: MOVSXD RAX,EDX",
            // A real response that happens to contain the word "error".
            "180127cd8: \"error handling\"",
        ] {
            assert_eq!(
                classify(body),
                Classification::Content,
                "should be content: {body:?}"
            );
        }
    }

    #[test]
    fn test_blank_body_is_not_content() {
        // Reading a blank body as "content" would claim the program has no such
        // function, which is a stronger statement than "the server said nothing".
        assert!(matches!(
            classify("   \n  "),
            Classification::Unrecognised(_)
        ));
    }

    #[test]
    fn test_matching_ignores_case() {
        assert!(matches!(
            classify("address is required"),
            Classification::Failure(_)
        ));
    }
}
