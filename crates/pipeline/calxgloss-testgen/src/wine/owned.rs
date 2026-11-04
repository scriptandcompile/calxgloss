//! Owned-process discipline: a launched process's identity is bound to an
//! **ownership token** at launch, and the token is rechecked before every
//! termination signal — never a bare-PID kill (P23.6, issue #400).
//!
//! A capture run stops its reference application when a budget runs out.
//! Stopping must hit the process the launch actually started, not whatever
//! happens to hold that PID now: a long capture that outlives its process
//! and finds a stranger in the slot must signal nothing. The token carries
//! what the OS says identifies the process — on Linux, the process start
//! time read from `/proc/<pid>/stat` — and every signal path asks the OS
//! again before it sends. P24 promotes this discipline to the scenario
//! contract; the type lands here first, where the capture run needs it.
//!
//! The stop path is a single signal, sent only through [`OwnedProcess::stop`]
//! — one path, and it always rechecks. The signal is the blunt one this
//! platform's standard library offers: Wine's server tears the guest's
//! process tree down when its client process dies, so stopping the client
//! stops the reference application with it.

use std::process::{Child, ExitStatus};

/// What identifies the launched process at the OS, read at launch.
///
/// `started_at` is the process start time in clock ticks (field 22 of
/// `/proc/<pid>/stat`) on Linux; it is `None` where the platform offers
/// no such stamp, and then the discipline degrades to the process handle
/// itself — an owned, unreaped `Child` cannot have its PID reused under
/// it, so the handle gate still holds, just with a coarser identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipToken {
    /// The process id bound at launch.
    pub pid: u32,
    /// The OS start stamp bound at launch, when the platform states one.
    pub started_at: Option<u64>,
}

/// Whether a signal may be sent to the bound process, decided from the
/// launch-time identity against a fresh OS read — before any signal.
///
/// This is the whole stale-PID rule spelled once: the token's own start
/// stamp must match what the OS now reports for that PID. A PID whose
/// process is gone reads as gone, never as a stranger; a PID answered by
/// a *different* process is the stale identity, and it gets no signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopDecision {
    /// The PID still answers to the very process the token bound.
    Signal,
    /// The PID is no longer in the process table at all.
    AlreadyGone,
    /// Something else holds the PID now: the token is stale.
    IdentityStale,
}

/// Decide a stop from the bound stamp and the fresh read, before any signal.
///
/// A platform that states no launch stamp (`None` bound) leaves identity to
/// the process handle — the caller's `try_wait` gate still refuses to
/// signal a reaped child — so it decides `Signal` and let the handle speak.
pub(crate) fn stop_decision(bound: Option<u64>, observed: Option<u64>) -> StopDecision {
    match (bound, observed) {
        (None, _) => StopDecision::Signal,
        (Some(_), None) => StopDecision::AlreadyGone,
        (Some(want), Some(seen)) if want == seen => StopDecision::Signal,
        (Some(_), Some(_)) => StopDecision::IdentityStale,
    }
}

/// What the process table now says identifies this PID, when the platform
/// can say: the start stamp read fresh from the OS. `None` means the PID
/// is not in the table (or this platform does not state a stamp).
fn observed_identity(pid: u32) -> Option<u64> {
    process_started_at(pid)
}

/// The process start stamp Linux keeps in `/proc/<pid>/stat` — field 22,
/// clock ticks at process start. The comm field (2) is parenthesized and
/// may hold spaces, so the numeric fields start after the last `)`.
#[cfg(target_os = "linux")]
fn process_started_at(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rfind(')')?;
    let fields: Vec<&str> = stat[after_comm + 2..].split(' ').collect();
    // Field 22 overall; fields 1-2 (pid, comm) precede this window, which
    // starts at field 3 (state), so starttime sits at index 22 - 3.
    fields.get(22 - 3).and_then(|f| f.parse().ok())
}

/// A platform that states no start stamp leaves `observed_identity` blind.
#[cfg(not(target_os = "linux"))]
fn process_started_at(_pid: u32) -> Option<u64> {
    None
}

/// What a stop attempt did — each outcome names whether a signal was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// The token rechecked clean; this exact process received the signal.
    Signaled,
    /// The process had already exited; nothing was signaled.
    AlreadyExited,
    /// The PID answered to a different identity; nothing was signaled.
    StaleIdentityUntouched,
}

/// A launched process paired with the identity bound at its launch.
///
/// Every termination signal goes through [`stop`](Self::stop): it
/// rechecks the token against the OS before sending, and the process
/// handle itself refuses to signal a child this runner has already
/// reaped. There is no path from here to a bare-PID kill.
#[derive(Debug)]
pub struct OwnedProcess {
    child: Child,
    token: OwnershipToken,
}

impl OwnedProcess {
    /// Bind the launched process's identity at launch.
    pub fn own(child: Child) -> Self {
        let token = OwnershipToken {
            pid: child.id(),
            started_at: process_started_at(child.id()),
        };
        Self { child, token }
    }

    /// Adopt a child with a token bound earlier — the shape a stale-PID
    /// test needs, and the shape a future P24 contract hands over.
    #[cfg(test)]
    pub(crate) fn with_token(child: Child, token: OwnershipToken) -> Self {
        Self { child, token }
    }

    /// The identity bound at launch.
    pub fn token(&self) -> OwnershipToken {
        self.token
    }

    /// Whether the process is running and unreaped, without stopping it.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    /// Wait for the process to exit and reap it.
    pub fn wait(&mut self) -> Result<ExitStatus, std::io::Error> {
        self.child.wait()
    }

    /// Stop the process: recheck the token, then send the terminating
    /// signal. There is exactly one signal path, and it always rechecks.
    pub fn stop(&mut self) -> Stopped {
        self.stop_with(|child| child.kill().is_ok())
    }

    /// The shared signal path: decide first, signal the handle second.
    fn stop_with(&mut self, signal: impl FnOnce(&mut Child) -> bool) -> Stopped {
        let decision = stop_decision(self.token.started_at, observed_identity(self.token.pid));
        match decision {
            StopDecision::AlreadyGone => Stopped::AlreadyExited,
            StopDecision::IdentityStale => Stopped::StaleIdentityUntouched,
            StopDecision::Signal => {
                // The handle gate: a child already exited and reaped by
                // this runner is off the table; a process still in it is
                // the one this launch made.
                match self.child.try_wait() {
                    Ok(Some(_)) => Stopped::AlreadyExited,
                    Err(_) => Stopped::AlreadyExited,
                    Ok(None) if signal(&mut self.child) => Stopped::Signaled,
                    Ok(None) => Stopped::AlreadyExited,
                }
            }
        }
    }

    /// Hand the child back — for a test that must clean up a process the
    /// token refused to touch. Production stops do not need this.
    #[cfg(test)]
    pub(crate) fn into_inner(self) -> Child {
        self.child
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn spawn_sleep(secs: u32) -> Child {
        Command::new("sleep")
            .arg(secs.to_string())
            .spawn()
            .expect("sleep should spawn")
    }

    #[test]
    fn a_matching_identity_earns_the_signal() {
        assert_eq!(
            stop_decision(Some(4000), Some(4000)),
            StopDecision::Signal,
            "the PID still answers to the process the token bound"
        );
    }

    #[test]
    fn a_different_identity_holding_the_pid_is_stale_and_gets_nothing() {
        assert_eq!(
            stop_decision(Some(4000), Some(9_999_999_999)),
            StopDecision::IdentityStale,
            "a stranger in the PID slot is never the owned process"
        );
    }

    #[test]
    fn a_gone_pid_reads_as_gone_not_stale() {
        assert_eq!(
            stop_decision(Some(4000), None),
            StopDecision::AlreadyGone,
            "no process at the PID: nothing to signal and nothing offended"
        );
    }

    #[test]
    fn an_unstampable_platform_degrades_to_the_handle_gate() {
        // Without a launch stamp the decision alone cannot tell stale from
        // live; the caller's try_wait gate still refuses a reaped child.
        assert_eq!(stop_decision(None, None), StopDecision::Signal);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_launch_stamp_is_read_for_a_live_process() {
        let child = spawn_sleep(30);
        let owned = OwnedProcess::own(child);
        assert!(
            owned.token().started_at.is_some(),
            "Linux states a start stamp for a live process"
        );
        let mut owned = owned;
        assert_eq!(owned.stop(), Stopped::Signaled);
        owned.wait().expect("the signaled process exits");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stale_pid_scenario_signals_nothing() {
        // A live process holds the token's PID under a *different* identity
        // — exactly what pid reuse looks like from the token's side. The
        // stop must refuse, and the stranger must still be running after.
        let stranger = spawn_sleep(30);
        let stale_token = OwnershipToken {
            pid: stranger.id(),
            started_at: Some(
                process_started_at(stranger.id())
                    .expect("the stranger has a start stamp")
                    .saturating_sub(1),
            ),
        };
        assert_ne!(
            stale_token.started_at,
            process_started_at(stranger.id()),
            "the forged stamp really differs from the live one"
        );

        let mut owned = OwnedProcess::with_token(stranger, stale_token);
        assert_eq!(
            owned.stop(),
            Stopped::StaleIdentityUntouched,
            "the token is stale: no signal is sent, at all"
        );
        assert_eq!(
            owned.try_wait().expect("try_wait runs"),
            None,
            "the untouched process is still running: the stop signaled nothing"
        );

        // The test's own cleanup, deliberately outside the token path.
        let mut child = owned.into_inner();
        child.kill().expect("cleanup kill");
        child.wait().expect("cleanup reap");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_already_exited_child_is_reported_and_never_signaled() {
        let mut owned = OwnedProcess::own(spawn_sleep(0));
        owned.wait().expect("sleep 0 exits and is reaped");
        assert_eq!(
            owned.stop(),
            Stopped::AlreadyExited,
            "a reaped child earns no signal, whatever its old PID now serves"
        );
    }
}
