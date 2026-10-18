//! Triage of decompiler warnings, in either engine's dialect.
//!
//! The decompiler writes its analysis failures into the pseudo-C itself —
//! Ghidra as `/* WARNING: ... */` banners, Kuna as terse `// slug` end-of-line
//! comments. Left unread they are cheap to miss and expensive to ignore: an
//! unrecovered jump table decompiles to an `UNRECOVERED_JUMPTABLE` local
//! called through a code pointer followed by a bare `return` (Ghidra), or a
//! truncated dispatch (Kuna), and the LLM translates that wreckage faithfully
//! into plausible, hollow Rust. This module reads the warnings out of the
//! decompiler body before a prompt is built, so the pipeline can name the
//! jump a human needs to look at instead of quietly translating around it.

/// An indirect jump the decompiler could not resolve into a switch: it gave
/// up on the jump table and treats the jump as a call. Ghidra says so with a
/// `Could not recover jumptable at 0x…` banner; Kuna truncates the function
/// and marks the line with a `jump-as-call` comment slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecoveredJumpTable {
    /// Virtual address of the indirect jump, when the warning names one.
    /// Ghidra's marker carries it; Kuna's inline slug comment does not.
    pub address: Option<u64>,

    /// The decompiler's stated reason, e.g. "Too many branches". Empty when
    /// the warning carries none.
    pub reason: String,
}

/// Find every unrecovered-jumptable warning in a decompiler body, in order
/// of appearance, in either engine's spelling.
///
/// The reading is deliberately string-level: the decompiler text is opaque
/// input, and the warning's own wording is the evidence — Ghidra's
/// `Could not recover jumptable at 0x<hex>. <reason>` marker, or Kuna's
/// `jump-as-call` slug inside a `//` comment (the slug carries no address).
/// One warning per line is assumed, as both engines emit them. A Ghidra
/// warning whose address does not parse as hexadecimal is dropped rather
/// than failing the scan: this is triage, not a gate, and a miss costs only
/// the log line it would have produced.
pub fn scan_unrecovered_jump_tables(decompiler_output: &str) -> Vec<UnrecoveredJumpTable> {
    const MARKER: &str = "Could not recover jumptable at ";
    // Kuna's inline warning slug for the jump table it truncates
    // (`// jt: jump-as-call`; the `jt: ` category prefix is only attached to
    // jumptable-tagged warnings, so the bare slug is accepted too).
    const KUNA_SLUG: &str = "jump-as-call";
    // Kuna's fallback slug form keeps unrecognized warnings in full behind a
    // `warn:` marker; match the warning's own stem so that form reads too.
    const KUNA_WARNING: &str = "Treating indirect jump as call";

    let mut found = Vec::new();
    for line in decompiler_output.lines() {
        if let Some(rest) = line.split(MARKER).nth(1) {
            // `rest` reads like "0x004712d7. Too many branches */": the address
            // token ends at whitespace (with a trailing period), the reason runs
            // to the comment closer.
            let mut tokens = rest.splitn(2, char::is_whitespace);
            let address_hex = tokens.next().unwrap_or("").trim_end_matches('.');
            let Ok(address) = u64::from_str_radix(address_hex.trim_start_matches("0x"), 16) else {
                continue;
            };
            let reason = tokens
                .next()
                .unwrap_or("")
                .trim_end_matches("*/")
                .trim()
                .to_string();
            found.push(UnrecoveredJumpTable {
                address: Some(address),
                reason,
            });
            continue;
        }
        // Kuna dialect: the signal is a slug inside a `//` comment, never a
        // marker. Several slugs share one comment, comma-separated.
        let Some(comment) = line.split_once("//").map(|(_, comment)| comment) else {
            continue;
        };
        let flagged = comment.split(',').any(|slug| {
            let slug = slug.trim();
            // A slug may carry a `category:` (or `warn:`) prefix.
            let bare = slug.rsplit(':').next().unwrap_or(slug).trim();
            bare == KUNA_SLUG || slug.contains(KUNA_WARNING)
        });
        if flagged {
            found.push(UnrecoveredJumpTable {
                address: None,
                reason: String::new(),
            });
        }
    }
    found
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A delay-load thunk body as Ghidra actually reports it: the helper
    /// call, the two warnings, and the indirect call the LLM would
    /// otherwise translate into a bare `return`.
    fn delay_load_body() -> &'static str {
        "\
void __fastcall DelayLoad_cef_string_utf16_clear(undefined4 param_1,undefined4 param_2)

{
  code *UNRECOVERED_JUMPTABLE;

  UNRECOVERED_JUMPTABLE =
       (code *)func_0x0049ce2d(&#38;ImgDelayDescr_0055e8c0,&#38;cef_string_utf16_clear_exref,param_2,param_1
                              );
                    /* WARNING: Could not recover jumptable at 0x004712d7. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}"
    }

    #[test]
    fn a_real_delay_load_warning_reads_with_address_and_reason() {
        let found = scan_unrecovered_jump_tables(delay_load_body());
        assert_eq!(
            found,
            vec![UnrecoveredJumpTable {
                address: Some(0x004712d7),
                reason: "Too many branches".to_string(),
            }],
            "the Ghidra banner reports once even though the body also carries \
             the 'Treating indirect jump as call' banner"
        );
    }

    #[test]
    fn several_warnings_report_in_order_of_appearance() {
        let body = "\
/* WARNING: Could not recover jumptable at 0x004010a0. Too many branches */
/* WARNING: Could not recover jumptable at 0x0040ff1f. Bad jumptable */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].address, Some(0x004010a0));
        assert_eq!(found[1].address, Some(0x0040ff1f));
        assert_eq!(found[1].reason, "Bad jumptable");
    }

    #[test]
    fn a_warning_without_a_reason_reads_empty() {
        let body = "/* WARNING: Could not recover jumptable at 0x180001234. */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, Some(0x180001234));
        assert_eq!(found[0].reason, "");
    }

    #[test]
    fn a_malformed_address_is_dropped_not_fatal() {
        let body = "\
/* WARNING: Could not recover jumptable at 0xZZZ. Bad jumptable */
/* WARNING: Could not recover jumptable at 0x4010a0. Too many branches */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1, "only the parseable warning reports");
        assert_eq!(found[0].address, Some(0x4010a0));
    }

    #[test]
    fn a_clean_body_finds_nothing() {
        let body = "\
undefined8 FUN_18003e750(undefined8 param_1)
{
  switch(param_1) {
  case 1:
    break;
  }
  return 0;
}";
        assert!(scan_unrecovered_jump_tables(body).is_empty());
    }

    // --- Kuna dialect ----------------------------------------------------

    /// The same unrecovered jump table as Kuna renders it (default
    /// `warnstyle inline`): the truncated dispatch carries a `// jt:
    /// jump-as-call` end-of-line comment instead of a Ghidra banner.
    #[test]
    fn a_kuna_slug_comment_reads_without_an_address() {
        let body = "\
undefined8 sub_140002490(undefined8 param_1)

{
  long lVar1;
  (*puVar4)(); // jt: jump-as-call
  return 0;
}";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(
            found,
            vec![UnrecoveredJumpTable {
                address: None,
                reason: String::new()
            }]
        );
    }

    #[test]
    fn a_kuna_slug_without_the_category_prefix_reads() {
        let body = "  (*code)(); // jump-as-call";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, None);
    }

    #[test]
    fn a_kuna_line_with_several_slugs_reports_once() {
        let body = "  switch(lVar3) { // jt: jump-as-call, no-return";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1, "one warning per line, as Kuna emits them");
    }

    #[test]
    fn a_kuna_warn_fallback_slug_reads() {
        // Unrecognized warning text keeps its full text behind `warn:`.
        let body = "  (*code)(); // warn: WARNING (jumptable): Treating indirect jump as call";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_kuna_body_without_the_slug_finds_nothing() {
        let body = "\
undefined8 sub_140002490(undefined8 param_1)
{
  switch(param_1) {
  case 1:
    break;
  }
  return 0;
}";
        assert!(scan_unrecovered_jump_tables(body).is_empty());
    }
}
