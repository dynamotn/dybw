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
//!
//! [`clipboard`] copies a value marked as secret and clears it later if it is unchanged.
//!
//! `keyring` takes `pam_bwss`'s handover from the user's kernel keyring (Linux only).
//!
//! [`enclave`] reaches the Secure Enclave and Touch ID through a Swift shim (macOS; a stub elsewhere).

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod clipboard;
pub mod enclave;
#[cfg(feature = "fake")]
mod fake;
#[cfg(target_os = "linux")]
pub mod keyring;
#[cfg(all(feature = "fake", not(debug_assertions)))]
compile_error!("the `fake` feature is for tests only and must not be built in release");
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
pub mod signals;

#[cfg(feature = "fake")]
pub use fake::Fake;

/// Largest `argv` + environment block read for one process.
pub const MAX_ARGS_BYTES: usize = 1 << 20;

/// Most argv entries, and most environment entries, kept for one process.
pub const MAX_ENTRIES: usize = 4096;

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

/// What makes a pid this process running this program and not a later one.
#[derive(Debug, Clone)]
pub struct Token {
    /// macOS audit-token pidversion (0 on Linux).
    pub version: u32,
    /// Process start time: microseconds since the epoch on macOS, clock ticks
    /// since boot on Linux. Only ever compared with itself.
    pub start: u64,
    /// The running image, as opaque bytes compared for equality: macOS
    /// unique id + pidversion + executable UUID, Linux exe link target +
    /// (dev, ino). It changes when the process `exec`s another program.
    pub image: Vec<u8>,
    /// Linux pidfd of the peer when the kernel gave one; kept open so the pid
    /// cannot be reused while this token lives.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pidfd: Option<Arc<OwnedFd>>,
}

impl Token {
    pub(crate) fn new(version: u32, start: u64, image: Vec<u8>, pidfd: Option<OwnedFd>) -> Self {
        Self { version, start, image, pidfd: pidfd.map(Arc::new) }
    }

    /// A token with no pidfd and no image, for fakes and tests.
    #[cfg(any(test, feature = "fake"))]
    pub fn plain(version: u32, start: u64) -> Self {
        Self::new(version, start, Vec::new(), None)
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

/// Whether a process's argv and environment could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Args {
    /// Read: `argv` and `env` are `Some`.
    Visible,
    /// The kernel keeps them from this user (another user's process, SIP, a zombie): `None`, which is normal.
    Withheld,
    /// Readable in principle (this user's process) but the read failed: too large, malformed, a size that moved
    /// between two reads. `None`, and a caller must treat the process as hiding something.
    Unreadable,
}

/// What the kernel says about a process now.
///
/// `exe` and `ppid` are the primary facts (ancestry). `argv` and `env` are
/// advisory and may only ever tighten a decision: `None` means "not visible"
/// (another user's process, SIP, EPERM/EINVAL/EACCES), never "empty", and a
/// caller must not read `None` as clean. Every `Process::of` error met while
/// walking ancestry must likewise be treated as "unknown".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub exe: PathBuf,
    pub ppid: u32,
    /// Same unit as [`Token::start`].
    pub start: u64,
    /// Same meaning as [`Token::image`].
    pub image: Vec<u8>,
    /// At most [`MAX_ENTRIES`] entries; `None` when not visible.
    pub argv: Option<Vec<OsString>>,
    /// At most [`MAX_ENTRIES`] entries; `None` when not visible.
    pub env: Option<Vec<(OsString, OsString)>>,
    /// `start` as a wall-clock time, to compare with file times; `None` when the boot time is unknown (Linux).
    pub started: Option<std::time::SystemTime>,
    /// Working directory; `None` when not visible. Read in the same window as the rest.
    pub cwd: Option<PathBuf>,
    /// macOS: the `LC_UUID` of the image the kernel runs (`p_uuid`), to tell whether a file on disk is that image;
    /// `None` on Linux or when the kernel has none.
    pub exe_uuid: Option<[u8; 16]>,
    /// Why `argv` and `env` are what they are.
    pub args: Args,
}

/// (ppid, start time, image) in one read.
type Id = (u32, u64, Vec<u8>);

fn read_id(pid: u32) -> Result<Id, Error> {
    let (ppid, start) = sys::ppid_start(pid)?;
    Ok((ppid, start, sys::image(pid)?))
}

/// The process was replaced (pid reused, or exec of another program) between
/// two reads when its start time or image moved.
fn unchanged(before: &Id, after: &Id) -> Result<(), Error> {
    if before.1 == after.1 && before.2 == after.2 { Ok(()) } else { Err(Error::Gone) }
}

/// Two reads that must agree: a pid reused between the start time and the
/// image reads would pair one process's start with another's image.
pub(crate) fn stable_id(pid: u32) -> Result<Id, Error> {
    let first = read_id(pid)?;
    unchanged(&first, &read_id(pid)?)?;
    Ok(first)
}

/// The home directory of `uid` in the password database (`getpwuid_r`), not from `HOME`, which whoever started
/// this process chose. `None` when there is no entry or its home is not an absolute path.
pub fn home_of(uid: u32) -> Option<PathBuf> {
    raw::home_of(uid, 1024)
}

type ArgsRead = (Option<Vec<OsString>>, Option<Vec<(OsString, OsString)>>);

/// What an argv/env read gave: `Ok((None, None))` is the kernel withholding them, an error is a failed read.
fn args_of(read: Result<ArgsRead, Error>) -> (ArgsRead, Args) {
    match read {
        Ok(read @ (Some(_), _)) => (read, Args::Visible),
        Ok(read) => (read, Args::Withheld),
        Err(_) => ((None, None), Args::Unreadable),
    }
}

/// Identify the peer of a connected Unix socket.
pub fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    sys::peer_of(sock)
}

impl Process {
    /// Read a process. `Err(Gone)` when it does not exist, or when it exited,
    /// was replaced or exec'd another program while being read. Arguments,
    /// environment and working directory that cannot be read (too large,
    /// malformed, a size that moved between two reads) are `None`, not an
    /// error: the exe, parent and start time are what ancestry rests on.
    pub fn of(pid: u32) -> Result<Self, Error> {
        let before = read_id(pid)?;
        let exe = sys::exe(pid)?;
        let ((argv, env), args) = args_of(sys::args(pid));
        let cwd = sys::cwd(pid).ok().flatten();
        unchanged(&before, &read_id(pid)?)?;
        let exe_uuid = sys::exe_uuid(&before.2);
        Ok(Self {
            exe,
            ppid: before.0,
            start: before.1,
            image: before.2,
            argv,
            env,
            cwd,
            started: sys::started(before.1),
            exe_uuid,
            args,
        })
    }
}

/// Is `peer` still the very process, running the very program, it was at
/// connect time?
pub fn still_same(peer: &Peer) -> bool {
    sys::alive(peer)
        && read_id(peer.pid).is_ok_and(|(_, start, image)| start == peer.token.start && image == peer.token.image)
}

/// Refuse debugger attachment to this process (macOS `PT_DENY_ATTACH`; on
/// Linux the equivalent, `PR_SET_DUMPABLE`, is set with the other hardening).
/// Call it first in the daemon. A hash of a path describes the file, not
/// necessarily the image that is running.
pub fn deny_attach() -> Result<(), Error> {
    sys::deny_attach()
}

/// The machine fingerprint a local unlock protector is bound to (ADR 0006): `IOPlatformUUID` on macOS, the content
/// of `/etc/machine-id` on Linux. Not a secret.
pub fn machine_id() -> Result<String, Error> {
    sys::machine_id()
}

/// The three questions the agent asks, so a test can answer them itself.
pub trait ProcessSource: Send + Sync {
    fn peer_of(&self, sock: BorrowedFd<'_>) -> Result<Peer, Error>;
    fn process(&self, pid: u32) -> Result<Process, Error>;
    fn still_same(&self, peer: &Peer) -> bool;
    /// The executable of `pid` (whose path was read as `exe`) opened for
    /// reading: on Linux the running image itself (`/proc/<pid>/exe`, even if
    /// the path now names another file), on macOS the file at `exe`.
    fn executable(&self, pid: u32, exe: &Path) -> std::io::Result<File>;
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
    fn executable(&self, pid: u32, exe: &Path) -> std::io::Result<File> {
        sys::executable(pid, exe)
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
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const MARKER: &str = "DYBW_PEER_MARKER";

    /// macOS withholds the environment of platform binaries (`/bin/sleep`),
    /// so the child is this test binary re-run on `child_body`.
    fn spawn_child(arg0: &str) -> Child {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.arg0(arg0)
            .args(["--exact", "tests::child_body"])
            .env(MARKER, "x=y")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        spawn(&mut cmd)
    }

    /// Linux refuses to exec a file some process still holds open for writing (ETXTBSY), and a fork in another test
    /// thread inherits the copy's write descriptor until its own exec: so no test forks while another copies.
    static FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn(cmd: &mut Command) -> Child {
        let _one = FORK.lock().unwrap();
        retry_busy(|| cmd.spawn()).unwrap()
    }

    /// A fork in another test thread can still hold a copied binary open for writing (ETXTBSY): retry briefly.
    fn retry_busy<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
        let mut tries = 0;
        loop {
            match f() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 100 => tries += 1,
                r => return r,
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_busy_text_file_is_retried_then_given_up() {
        let busy = || Err::<(), _>(std::io::Error::from(std::io::ErrorKind::ExecutableFileBusy));
        let mut calls = 0;
        assert!(
            retry_busy(|| {
                calls += 1;
                if calls < 3 { busy() } else { Ok(()) }
            })
            .is_ok()
        );
        assert_eq!(calls, 3);
        assert_eq!(retry_busy(busy).unwrap_err().kind(), std::io::ErrorKind::ExecutableFileBusy);
    }

    /// Right after the exec the kernel may not have set the new arguments up yet (an empty or briefly withheld cmdline, Linux): read the
    /// process again until its argv is there, for up to 5 s.
    fn process_of(child: &Child) -> Process {
        let read = |_| {
            std::thread::sleep(Duration::from_millis(1));
            Process::of(child.id()).unwrap()
        };
        // Withheld (EACCES) is also seen while the exec is in flight; Unreadable (oversized) is final.
        let settled = |p: &Process| p.args == Args::Unreadable || p.argv.as_ref().is_some_and(|a| !a.is_empty());
        (0..5000).map(read).find(settled).unwrap() // settled within 5 s
    }

    fn sleeper() -> Child {
        spawn_child("child")
    }

    /// A no-op in the normal run; the child sleeps (the marker is its cue).
    #[test]
    fn child_body() {
        let secs = if std::env::var_os(MARKER).is_some() { 30 } else { 0 };
        std::thread::sleep(Duration::from_secs(secs));
    }

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn peer_of_a_socketpair_is_self() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = peer_of_stream(&a).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.uid, euid());
        assert!(!peer.token.image.is_empty());
        assert!(still_same(&peer));
        let me = Process::of(peer.pid).unwrap();
        assert_eq!((me.start, &me.image), (peer.token.start, &peer.token.image));
        assert_eq!(Os.process(peer.pid).unwrap(), me);
        assert!(Os.still_same(&Os.peer_of(a.as_fd()).unwrap()));
        assert!(peer_of(a.as_fd()).is_ok());
        assert!(me.argv.is_some() && me.env.is_some());
    }

    #[test]
    fn a_child_reads_back_exe_argv_env_and_ppid() {
        let mut child = sleeper();
        let p = process_of(&child);
        assert_eq!(p.ppid, std::process::id());
        assert_eq!(p.exe, std::env::current_exe().unwrap().canonicalize().unwrap());
        assert_eq!(p.argv.unwrap().last().unwrap(), "tests::child_body");
        assert!(p.env.unwrap().iter().any(|(k, v)| k == MARKER && v == "x=y"));
        let here = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(p.cwd.unwrap().canonicalize().unwrap(), here);
        assert!(p.started.unwrap() <= std::time::SystemTime::now());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn an_empty_argv0_stays_an_argv_entry() {
        let mut child = spawn_child("");
        let argv = process_of(&child).argv.unwrap();
        assert_eq!(argv.first().unwrap(), "");
        assert_eq!(argv.get(1).unwrap(), "--exact");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn argv_survives_every_path_length_residue() {
        let dir = tempfile::tempdir().unwrap();
        let me = std::env::current_exe().unwrap();
        for n in 1..=8usize {
            let copy = dir.path().join("a".repeat(n));
            {
                let _one = FORK.lock().unwrap();
                std::fs::copy(&me, &copy).unwrap();
            }
            for arg0 in ["zero", ""] {
                let mut child = spawn(
                    Command::new(&copy)
                        .arg0(arg0)
                        .args(["--exact", "tests::child_body"])
                        .env(MARKER, "x=y")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null()),
                );
                let argv = process_of(&child).argv.unwrap();
                child.kill().unwrap();
                child.wait().unwrap();
                assert_eq!(argv, [arg0, "--exact", "tests::child_body"], "name length {n}");
            }
        }
    }

    #[test]
    fn an_exited_child_is_gone_and_not_the_same() {
        let mut child = sleeper();
        let peer = sys::peer_of_pid(child.id()).unwrap();
        assert!(still_same(&peer));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!still_same(&peer));
        assert_eq!(Process::of(peer.pid), Err(Error::Gone));
    }

    #[test]
    fn a_child_that_execs_another_program_is_not_the_same() {
        let mut child = spawn(Command::new("/bin/sh").args(["-c", "read x; exec /bin/sleep 30"]).stdin(Stdio::piped()));
        let peer = sys::peer_of_pid(child.id()).unwrap();
        assert!(still_same(&peer));
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        let begun = Instant::now();
        while still_same(&peer) {
            assert!(begun.elapsed() < Duration::from_secs(10), "exec went unnoticed");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
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
    fn the_home_of_this_user_is_absolute() {
        assert!(home_of(euid()).is_some_and(|h| h.is_absolute()));
    }

    #[test]
    fn the_executable_opened_is_the_running_one() {
        use std::os::unix::fs::MetadataExt;
        let me = Process::of(std::process::id()).unwrap();
        let opened = Os.executable(std::process::id(), &me.exe).unwrap().metadata().unwrap();
        let on_disk = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
        assert_eq!((opened.dev(), opened.ino()), (on_disk.dev(), on_disk.ino()));
        assert_eq!(me.exe_uuid.is_some(), cfg!(target_os = "macos"));
        assert_eq!(me.args, Args::Visible);
    }

    #[test]
    fn withheld_arguments_are_told_apart_from_a_failed_read() {
        assert_eq!(args_of(Ok((None, None))).1, Args::Withheld);
        assert_eq!(args_of(Ok((Some(vec![]), Some(vec![])))).1, Args::Visible);
        for e in [Error::TooLarge, Error::Malformed, Error::Os(libc::ENOMEM)] {
            assert_eq!(args_of(Err(e)), ((None, None), Args::Unreadable));
        }
    }

    /// Arguments past the cap are "not visible", and the process is still read (Linux: macOS cannot exec that much).
    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_arguments_are_hidden_not_an_error() {
        // One argument is capped at 128 KiB (MAX_ARG_STRLEN): twenty of 64 KiB pass the 1 MiB cap.
        let big = vec!["a".repeat(64 << 10); 20];
        let mut child = spawn(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::child_body"])
                .args(&big)
                .env(MARKER, "x=y")
                .stdin(Stdio::null())
                .stdout(Stdio::null()),
        );
        let p = process_of(&child);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(p.ppid, std::process::id());
        assert_eq!((p.argv, p.args), (None, Args::Unreadable));
    }

    #[test]
    fn deny_attach_succeeds() {
        deny_attach().unwrap();
    }

    #[test]
    fn a_process_replaced_mid_read_is_gone() {
        let id = |start: u64, image: &[u8]| (1, start, image.to_vec());
        assert_eq!(unchanged(&id(1, b"a"), &id(1, b"a")), Ok(()));
        assert_eq!(unchanged(&id(1, b"a"), &id(2, b"a")), Err(Error::Gone));
        assert_eq!(unchanged(&id(1, b"a"), &id(1, b"b")), Err(Error::Gone));
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
