//! Per-function decompile budgets for the Kuna engine (issue #211).
//!
//! Kuna's embeddable engine carries three per-function watchdogs, and each
//! one is a knob the calxgloss `[analysis]` config block can set: the
//! instruction bound one function's flow may follow (`maxinstruction`), the
//! wall-clock budget the whole per-function drive may spend (the
//! `--max-fn-seconds` watchdog, armed on the architecture as
//! `kuna_fn_budget`), and the resident-set growth one function may cause
//! (the `--max-fn-memory` watchdog, a process-wide limit in the engine's
//! `kuna_fnmemory` module). A budget that trips fails that one function by
//! name — see [`KunaError::DecompileBudgetExceeded`](crate::KunaError::DecompileBudgetExceeded)
//! — so one obfuscated function cannot exhaust a memory-constrained box or
//! hang the run.
//!
//! An unset knob leaves Kuna's own default in force: 100 000 instructions,
//! no wall-clock budget, no memory limit. `Some(0)` means the same for all
//! three — Kuna's CLI convention that `0` disables the watchdog — so a
//! config that writes `max_fn_seconds = 0` asks for the default, not for a
//! budget that trips on every function.

use std::time::Duration;

use crate::engine::KunaProgram;
use crate::error::{KunaError, Result};

/// The per-function decompile budgets a `kuna` run arms, `None` for
/// "leave Kuna's default".
///
/// The instruction and time budgets live on the loaded program's
/// architecture and so bind exactly one program. The memory budget is
/// process-wide in the engine (it measures the process's resident set),
/// which one-engine-per-run makes harmless — but it is why a
/// [`KunaSource`](crate::KunaSource) load applies it at most once, at load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KunaBudget {
    /// The instructions one function's flow may follow (Kuna's
    /// `maxinstruction`); Kuna's default is 100 000.
    pub max_instructions: Option<u64>,
    /// The wall-clock seconds one function's whole decompile may spend
    /// (Kuna's `--max-fn-seconds`); Kuna's default is no budget.
    pub max_fn_seconds: Option<u64>,
    /// The MiB of resident-set growth one function may cause (Kuna's
    /// `--max-fn-memory`); Kuna's default is no limit.
    pub max_fn_memory_mib: Option<u64>,
}

impl KunaBudget {
    /// Refuse a knob the platform cannot enforce, before anything loads.
    ///
    /// The memory watchdog decides by watching the process's resident set;
    /// where that cannot be read the limit could never fire, so arming it
    /// would be a silent no-op — the same refusal Kuna's CLI makes for
    /// `--max-fn-memory`.
    pub fn validate(&self) -> Result<()> {
        if self.max_fn_memory_mib.is_some_and(|mib| mib > 0)
            && !kuna_decomp::kuna_fnmemory::supported()
        {
            return Err(KunaError::BudgetUnsupported {
                knob: "max_fn_memory_mib",
                reason: "this platform does not report the process resident set, so a \
                         per-function memory limit could never fire"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Arm the budgets on a freshly loaded program.
    ///
    /// Unset knobs (and `Some(0)`) change nothing, keeping the defaults
    /// Kuna's own reset installed. The instruction bound saturates at
    /// `u32::MAX` — the engine's bound is a 32-bit count, and a bound past
    /// it is unreachable anyway.
    pub(crate) fn apply(&self, program: &mut KunaProgram) {
        let arch = program.program.arch_mut();
        if let Some(max) = self.max_instructions.filter(|max| *max > 0) {
            arch.max_instructions = max.min(u64::from(u32::MAX)) as u32;
        }
        if let Some(secs) = self.max_fn_seconds.filter(|secs| *secs > 0) {
            arch.kuna_fn_budget = Some(Duration::from_secs(secs));
        }
        if let Some(mib) = self.max_fn_memory_mib.filter(|mib| *mib > 0) {
            kuna_decomp::kuna_fnmemory::set_limit_mib(mib);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine;

    #[test]
    fn budget_knobs_reach_the_engine_and_unset_knobs_leave_kunas_defaults() {
        // One test touches the process-wide memory limit on purpose: the
        // engine keeps it in a global, so two tests arming it at once would
        // race. The default half runs before anything is armed.
        let fixture =
            calxgloss_testfixtures::load_target().expect("the fixture target builds and validates");
        let mut program = engine::load(fixture.path()).expect("the fixture must load");

        // Kuna's own defaults, before any knob: 100 000 instructions, no
        // wall-clock budget, no memory limit.
        let defaults = KunaBudget::default();
        defaults.apply(&mut program);
        let arch = program.program.arch();
        assert_eq!(
            arch.max_instructions, 100_000,
            "Kuna's maxinstruction default"
        );
        assert_eq!(
            arch.kuna_fn_budget, None,
            "Kuna arms no time budget by default"
        );
        assert_eq!(
            kuna_decomp::kuna_fnmemory::limit_mib(),
            0,
            "Kuna sets no memory limit by default"
        );

        // Every knob set reaches the engine where Kuna keeps it. The memory
        // limit is huge on purpose — this test proves arming, and a limit
        // that fires would poison other tests sharing the process.
        let budget = KunaBudget {
            max_instructions: Some(5_000),
            max_fn_seconds: Some(30),
            max_fn_memory_mib: Some(1_000_000),
        };
        budget.apply(&mut program);
        let arch = program.program.arch();
        assert_eq!(arch.max_instructions, 5_000);
        assert_eq!(arch.kuna_fn_budget, Some(Duration::from_secs(30)));
        assert_eq!(kuna_decomp::kuna_fnmemory::limit_mib(), 1_000_000);

        // `Some(0)` is Kuna's disable convention: it asks for the default,
        // not for a watchdog that trips on every function.
        let zeros = KunaBudget {
            max_instructions: Some(0),
            max_fn_seconds: Some(0),
            max_fn_memory_mib: Some(0),
        };
        zeros.apply(&mut program);
        let arch = program.program.arch();
        assert_eq!(
            arch.max_instructions, 5_000,
            "0 leaves the armed bound alone"
        );
        assert_eq!(arch.kuna_fn_budget, Some(Duration::from_secs(30)));
        assert_eq!(kuna_decomp::kuna_fnmemory::limit_mib(), 1_000_000);

        // Leave the process-wide limit as the engine shipped it.
        kuna_decomp::kuna_fnmemory::set_limit_mib(0);
    }
}
