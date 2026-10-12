//! Triage of Ghidra decompiler warnings.
//!
//! Ghidra writes its analysis failures into the pseudo-C itself as
//! `/* WARNING: ... */` comments. Left unread they are cheap to miss and
//! expensive to ignore: an unrecovered jump table decompiles to an
//! `UNRECOVERED_JUMPTABLE` local called through a code pointer followed by
//! a bare `return`, and the LLM translates that wreckage faithfully into
//! plausible, hollow Rust. This module reads the warnings out of the
//! decompiler body before a prompt is built, so the pipeline can name the
//! address a human needs to look at instead of quietly translating around
//! it.

/// An indirect jump Ghidra could not resolve into a switch: it gave up on
/// the jump table at `address` ("Could not recover jumptable"), emitted an
/// `UNRECOVERED_JUMPTABLE` local, and treats the jump as a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecoveredJumpTable {
    /// Virtual address of the indirect jump Ghidra gave up on.
    pub address: u64,

    /// Ghidra's stated reason, e.g. "Too many branches". Empty when the
    /// warning carries none.
    pub reason: String,
}

/// Find every unrecovered-jumptable warning in a decompiler body, in order
/// of appearance.
///
/// The reading is deliberately string-level: the decompiler text is opaque
/// input, and the warning's own wording — `Could not recover jumptable at
/// 0x<hex>. <reason>` — is the evidence. One warning per line is assumed,
/// as Ghidra emits them. A warning whose address does not parse as
/// hexadecimal is dropped rather than failing the scan: this is triage,
/// not a gate, and a miss costs only the log line it would have produced.
pub fn scan_unrecovered_jump_tables(decompiler_output: &str) -> Vec<UnrecoveredJumpTable> {
    const MARKER: &str = "Could not recover jumptable at ";

    let mut found = Vec::new();
    for line in decompiler_output.lines() {
        let Some(rest) = line.split(MARKER).nth(1) else {
            continue;
        };
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
        found.push(UnrecoveredJumpTable { address, reason });
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
                address: 0x004712d7,
                reason: "Too many branches".to_string(),
            }]
        );
    }

    #[test]
    fn several_warnings_report_in_order_of_appearance() {
        let body = "\
/* WARNING: Could not recover jumptable at 0x004010a0. Too many branches */
/* WARNING: Could not recover jumptable at 0x0040ff1f. Bad jumptable */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].address, 0x004010a0);
        assert_eq!(found[1].address, 0x0040ff1f);
        assert_eq!(found[1].reason, "Bad jumptable");
    }

    #[test]
    fn a_warning_without_a_reason_reads_empty() {
        let body = "/* WARNING: Could not recover jumptable at 0x180001234. */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, 0x180001234);
        assert_eq!(found[0].reason, "");
    }

    #[test]
    fn a_malformed_address_is_dropped_not_fatal() {
        let body = "\
/* WARNING: Could not recover jumptable at 0xZZZ. Bad jumptable */
/* WARNING: Could not recover jumptable at 0x4010a0. Too many branches */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1, "only the parseable warning reports");
        assert_eq!(found[0].address, 0x4010a0);
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
}
