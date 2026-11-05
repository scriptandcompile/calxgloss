//! The scenario run's terminal seam: a host PTY the target program runs
//! on, so scripted input, resizes, and console signals travel the same
//! path a human operator would use. Unix only — the scenario lane's
//! Wine toolchain stands on unix hosts.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::process::Stdio;

use anyhow::{Context as _, Result};
use calxgloss_types::TerminalGeometry;

/// An open master/slave PTY pair, sized to the contract's geometry.
#[derive(Debug)]
pub(super) struct Pty {
    master: OwnedFd,
    slave: Option<OwnedFd>,
}

/// What Wine's terminal console does with the pty line discipline:
///
/// The slave is left in the canonical default `openpty` gives it —
/// Wine's console driver reworks the terminal itself and drops it into
/// `~ICRNL`, so a line terminator written as `\n` arrives at the console
/// as a bare newline the Windows console never reads as Enter (the line
/// sits unread until it is lost). A terminator written as `\r` arrives
/// as `\r\n`, and the console reads the line. So every input line ends
/// with a carriage return: the console's Enter, not the tty's newline.
pub(super) const INPUT_LINE_END: &[u8] = b"\r";

impl Pty {
    /// Open the pair with the contract's starting geometry.
    pub(super) fn open(cols: u16, rows: u16) -> Result<Self> {
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty writes the two descriptors it reports; the rest
        // of this block wraps them in OwnedFd only after success.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        };
        if opened != 0 {
            return Err(IoError::last_os_error()).context("could not open the scenario PTY");
        }
        Ok(Self {
            // SAFETY: the fds were just created by openpty and are owned here.
            master: unsafe { OwnedFd::from_raw_fd(master) },
            slave: Some(unsafe { OwnedFd::from_raw_fd(slave) }),
        })
    }

    /// Three independent stdio handles for the child. The parent keeps
    /// its own slave open until [`close_slave`](Self::close_slave) after
    /// the spawn — until then an exit is not yet visible as an EOF.
    pub(super) fn child_stdio(&self) -> Result<(Stdio, Stdio, Stdio)> {
        let slave = self
            .slave
            .as_ref()
            .context("the scenario PTY's slave side is already closed")?;
        let handle = || -> Result<Stdio> {
            // SAFETY: dup only reports a fresh descriptor the caller owns.
            let duplicated = unsafe { libc::dup(slave.as_raw_fd()) };
            if duplicated < 0 {
                return Err(IoError::last_os_error()).context("could not dup the PTY slave");
            }
            // SAFETY: the fd was just created by dup and is owned here.
            Ok(Stdio::from(unsafe { OwnedFd::from_raw_fd(duplicated) }))
        };
        Ok((handle()?, handle()?, handle()?))
    }

    /// Close the parent's slave side: from here, the child exiting reads
    /// as EOF on the master.
    pub(super) fn close_slave(&mut self) {
        drop(self.slave.take());
    }

    /// Type bytes onto the terminal.
    pub(super) fn write_input(&self, bytes: &[u8]) -> IoResult<()> {
        let mut written = 0;
        while written < bytes.len() {
            // SAFETY: the buffer outlives the call; the slice is readable.
            let n = unsafe {
                libc::write(
                    self.master.as_raw_fd(),
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                )
            };
            if n < 0 {
                let error = IoError::last_os_error();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            written += n as usize;
        }
        Ok(())
    }

    /// Move the terminal's geometry under the running program.
    pub(super) fn resize(&self, cols: u16, rows: u16) -> IoResult<()> {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads the winsize struct pointed at; it outlives the call.
        let rc = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
        if rc != 0 {
            return Err(IoError::last_os_error());
        }
        Ok(())
    }

    /// Read the live terminal's geometry back off the master — what the
    /// terminal is rendering, never what was declared.
    pub(super) fn geometry(&self) -> IoResult<TerminalGeometry> {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ writes the winsize struct it is given, and the
        // master fd is live for as long as the pair stands.
        let ok = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
        if ok != 0 {
            return Err(IoError::last_os_error());
        }
        Ok(TerminalGeometry {
            cols: size.ws_col,
            rows: size.ws_row,
        })
    }

    /// Whether output is waiting, bounded by `timeout_ms` — the loop's
    /// interaction clock advances on every wake.
    pub(super) fn output_ready(&self, timeout_ms: i32) -> IoResult<bool> {
        let mut poll = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pollfd array is one live entry.
        let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        if ready < 0 {
            let error = IoError::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(ready > 0)
    }

    /// One output chunk; `None` once the far side is gone (EIO: the child
    /// exited and every slave handle is closed).
    pub(super) fn read_output(&self) -> IoResult<Option<Vec<u8>>> {
        loop {
            let mut buffer = [0u8; 8192];
            // SAFETY: the buffer is writable and outlives the call.
            let n = unsafe {
                libc::read(
                    self.master.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                let error = IoError::last_os_error();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() == Some(libc::EIO) {
                    return Ok(None);
                }
                return Err(error);
            }
            if n == 0 {
                return Ok(None);
            }
            return Ok(Some(buffer[..n as usize].to_vec()));
        }
    }
}
