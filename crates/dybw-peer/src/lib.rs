//! Who is on the other end of a Unix socket, and what is above them.
//!
//! This is the only crate in the workspace that may use `unsafe` (and `libc`):
//! every block sits next to a `// SAFETY:` argument and the public API is
//! safe, returning owned values.
//!
//! Identity is the pid plus a token that survives pid reuse: macOS reads the
//! audit token (pid + pidversion) and the process start time; Linux keeps the
//! pidfd when the kernel offers one (`SO_PEERPIDFD`) and always the start
//! time. [`still_same`] re-checks it.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::OsString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "fake")]
mod fake;
#[cfg(target_os = "linux")]
mod linux;
mod parse;
#[cfg(target_os = "linux")]
use linux as sys;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
use mac as sys;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("dybw-peer supports Linux and macOS only");
mod raw;

#[cfg(feature = "fake")]
pub use fake::Fake;

/// Largest `argv` + environment block read for one process.
pub const MAX_ARGS_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The process is gone (or its pid never named one).
    #[error("no such process")]
    Gone,
    /// A system call failed with this errno.
    #[error("system call failed: errno {0}")]
    Os(i32),
    /// The kernel returned data this crate cannot make sense of.
    #[error("unexpected data from the kernel")]
    Malformed,
    /// `argv` + environment exceed [`MAX_ARGS_BYTES`].
    #[error("process arguments too large")]
    TooLarge,
}

impl Error {
    pub(crate) fn from_errno(errno: i32) -> Self {
        if errno == libc::ESRCH { Self::Gone } else { Self::Os(errno) }
    }
}

/// What makes a pid this process and not a later one with the same number.
#[derive(Debug, Clone)]
pub struct Token {
    /// macOS audit-token pidversion (0 on Linux).
    pub version: u32,
    /// Process start time: microseconds since the epoch on macOS, clock ticks
    /// since boot on Linux. Only ever compared with itself.
    pub start: u64,
    /// Linux pidfd of the peer when the kernel gave one; kept open so the pid
    /// cannot be reused while this token lives.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pidfd: Option<Arc<OwnedFd>>,
}

impl Token {
    pub(crate) fn new(version: u32, start: u64, pidfd: Option<OwnedFd>) -> Self {
        Self { version, start, pidfd: pidfd.map(Arc::new) }
    }

    /// A token with no pidfd, for fakes and tests.
    pub fn plain(version: u32, start: u64) -> Self {
        Self::new(version, start, None)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn pidfd(&self) -> Option<&OwnedFd> {
        self.pidfd.as_deref()
    }
}

/// The process on the other end of a connected socket, at connect time.
#[derive(Debug, Clone)]
pub struct Peer {
    pub pid: u32,
    /// Effective uid of the peer.
    pub uid: u32,
    pub token: Token,
}

/// What the kernel says about a process now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub exe: PathBuf,
    pub ppid: u32,
    /// Same unit as [`Token::start`].
    pub start: u64,
    /// Empty when the process belongs to another user and the kernel refuses.
    pub argv: Vec<OsString>,
    /// Same caveat as `argv`.
    pub env: Vec<(OsString, OsString)>,
}

/// The process was replaced between two reads when its start time moved.
fn unchanged(before: u64, after: u64) -> Result<(), Error> {
    if before == after { Ok(()) } else { Err(Error::Gone) }
}

/// Identify the peer of a connected Unix socket.
pub fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    sys::peer_of(sock)
}

impl Process {
    /// Read a process. `Err(Gone)` when it does not exist, or when it exited
    /// (or was replaced) while being read.
    pub fn of(pid: u32) -> Result<Self, Error> {
        let (ppid, start) = sys::ppid_start(pid)?;
        let exe = sys::exe(pid)?;
        let (argv, env) = sys::args(pid)?;
        unchanged(start, sys::ppid_start(pid)?.1)?;
        Ok(Self { exe, ppid, start, argv, env })
    }
}

/// Is `peer` still the very process it was at connect time?
pub fn still_same(peer: &Peer) -> bool {
    sys::still_same(peer)
}

/// Refuse debugger attachment to this process (macOS `PT_DENY_ATTACH`; on
/// Linux the equivalent, `PR_SET_DUMPABLE`, is set with the other hardening).
pub fn deny_attach() -> Result<(), Error> {
    sys::deny_attach()
}

/// The three questions the agent asks, so a test can answer them itself.
pub trait ProcessSource: Send + Sync {
    fn peer_of(&self, sock: BorrowedFd<'_>) -> Result<Peer, Error>;
    fn process(&self, pid: u32) -> Result<Process, Error>;
    fn still_same(&self, peer: &Peer) -> bool;
}

/// The real thing: the operating system.
#[derive(Debug, Default, Clone, Copy)]
pub struct Os;

impl ProcessSource for Os {
    fn peer_of(&self, sock: BorrowedFd<'_>) -> Result<Peer, Error> {
        peer_of(sock)
    }
    fn process(&self, pid: u32) -> Result<Process, Error> {
        Process::of(pid)
    }
    fn still_same(&self, peer: &Peer) -> bool {
        still_same(peer)
    }
}

/// Convenience for callers holding a std or tokio stream.
pub fn peer_of_stream(stream: &impl AsFd) -> Result<Peer, Error> {
    peer_of(stream.as_fd())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};

    const MARKER: &str = "DYBW_PEER_MARKER";

    /// macOS withholds the environment of platform binaries (`/bin/sleep`),
    /// so the child is this test binary re-run on `child_body`.
    fn sleeper() -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::child_body"])
            .env(MARKER, "x=y")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// A no-op in the normal run; the child sleeps (the marker is its cue).
    #[test]
    fn child_body() {
        let secs = if std::env::var_os(MARKER).is_some() { 30 } else { 0 };
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    #[test]
    fn peer_of_a_socketpair_is_self() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = peer_of_stream(&a).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.uid, euid());
        assert!(still_same(&peer));
        let me = Process::of(peer.pid).unwrap();
        assert_eq!(me.start, peer.token.start);
        assert_eq!(Os.process(peer.pid).unwrap(), me);
        assert!(Os.still_same(&Os.peer_of(a.as_fd()).unwrap()));
        assert!(peer_of(a.as_fd()).is_ok());
    }

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_child_reads_back_exe_argv_env_and_ppid() {
        let mut child = sleeper();
        let p = Process::of(child.id()).unwrap();
        assert_eq!(p.ppid, std::process::id());
        assert_eq!(p.exe, std::env::current_exe().unwrap().canonicalize().unwrap());
        assert_eq!(p.argv.last().unwrap(), "tests::child_body");
        assert!(p.env.iter().any(|(k, v)| k == MARKER && v == "x=y"));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn an_exited_child_is_gone_and_not_the_same() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut child = sleeper();
        let mut peer = peer_of_stream(&a).unwrap();
        peer.pid = child.id();
        peer.token.start = Process::of(child.id()).unwrap().start;
        assert!(still_same(&peer));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!still_same(&peer));
        assert_eq!(Process::of(peer.pid), Err(Error::Gone));
    }

    #[test]
    fn a_reused_pid_with_another_start_is_not_the_same() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut peer = peer_of_stream(&a).unwrap();
        peer.token.start += 1;
        assert!(!still_same(&peer));
    }

    #[test]
    fn a_pid_that_cannot_exist_is_gone() {
        assert_eq!(Process::of(u32::MAX - 1), Err(Error::Gone));
    }

    #[test]
    fn deny_attach_succeeds() {
        deny_attach().unwrap();
    }

    #[test]
    fn a_process_replaced_mid_read_is_gone() {
        assert_eq!(unchanged(1, 1), Ok(()));
        assert_eq!(unchanged(1, 2), Err(Error::Gone));
    }

    #[test]
    fn errors_map_and_print() {
        assert_eq!(Error::from_errno(libc::ESRCH), Error::Gone);
        assert_eq!(Error::from_errno(libc::EPERM), Error::Os(libc::EPERM));
        for e in [Error::Gone, Error::Os(1), Error::Malformed, Error::TooLarge] {
            assert!(!e.to_string().is_empty());
        }
        let t = Token::plain(1, 2);
        assert!(t.pidfd().is_none());
    }
}
