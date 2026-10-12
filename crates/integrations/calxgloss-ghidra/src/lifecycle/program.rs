//! The wrong-program guard — the pre-scan half of the 2026-10-08 incident fix.
//!
//! GhidraMCP answers every query from whichever program is *current*, and the
//! 6.x bridge can hold several programs open at once. The 2026-10-08 incident
//! had several GUI CodeBrowser windows open: the bridge answered a scan's
//! listing from one program and its name searches from another, so the scan
//! skipped its whole (wrong-program) listing with per-function warnings and
//! nearly persisted an empty record as if the scan were clean. The guard runs
//! before any scan: it verifies the server is serving the scan target,
//! switches to it when it is open but not current, and fails fast — naming
//! the programs that *are* open — when it is not open at all.

use tracing::{debug, info};

use crate::client::{GhidraClient, GhidraError, Result};

/// What the guard had to do to make the scan target current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramMatch {
    /// The target was already the current program — nothing was touched.
    AlreadyCurrent,
    /// The target was open but not current — the guard switched to it.
    Switched,
}

/// Verify the server is serving `target` before any scan runs against it.
///
/// `target` names the binary the scan is for, e.g. `eqmain.dll`, matched
/// case-insensitively against the program names the server lists. When the
/// target is open but not current, [`switch_program`](GhidraClient::switch_program)
/// makes it current and every later query answers from it — the run proceeds
/// against the program it actually asked for.
///
/// # Errors
///
/// - [`GhidraError::WrongProgram`] when the target is not open at all; the
///   message names the programs that *are* open.
/// - Any transport or reported error from the listing or the switch itself.
pub async fn ensure_current_program(client: &GhidraClient, target: &str) -> Result<ProgramMatch> {
    let programs = client.open_programs().await?;
    let target_name = programs
        .iter()
        .find(|program| program.name.eq_ignore_ascii_case(target));
    match target_name {
        Some(program) if program.is_current => {
            debug!(program = %program.name, "GhidraMCP is already serving the scan target");
            Ok(ProgramMatch::AlreadyCurrent)
        }
        Some(program) => {
            let previous = programs
                .iter()
                .find(|program| program.is_current)
                .map(|program| program.name.as_str())
                .unwrap_or("none");
            client.switch_program(&program.name).await?;
            info!(
                target = %program.name,
                previous,
                "Switched GhidraMCP to the scan target"
            );
            Ok(ProgramMatch::Switched)
        }
        None => {
            let open = programs
                .iter()
                .map(|program| program.name.clone())
                .collect();
            Err(GhidraError::WrongProgram {
                target: target.to_string(),
                open,
            })
        }
    }
}
