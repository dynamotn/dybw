//! Linux: SO_PEERCRED / SO_PEERPIDFD and /proc.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use crate::parse::{self, Env};
use crate::raw::{errno, getsockopt, within_cap};
use crate::{Error, Peer, Token};

/// `SO_PEERPIDFD` (kernel 6.5+); not in every libc release.
const SO_PEERPIDFD: libc::c_int = 77;

pub(crate) fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 12];
    let n = getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut buf)?;
    let (pid, uid) = buf.get(..n).and_then(parse::ucred).ok_or(Error::Malformed)?;
    let pidfd = peer_pidfd(fd);
    let (_, start) = ppid_start(pid)?;
    Ok(Peer { pid, uid, token: Token::new(0, start, pidfd) })
}

/// The pidfd of the peer, or `None` on a kernel without `SO_PEERPIDFD`
/// (the start time then carries the identity alone).
fn peer_pidfd(fd: libc::c_int) -> Option<OwnedFd> {
    let mut buf = [0u8; 4];
    getsockopt(fd, libc::SOL_SOCKET, SO_PEERPIDFD, &mut buf).ok()?;
    let raw = i32::from_ne_bytes(buf);
    // SAFETY: on success the kernel installed a new descriptor in this
    // process for the pidfd and nothing else owns it; it is closed once, by
    // the OwnedFd.
    (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) })
}

pub(crate) fn still_same(peer: &Peer) -> bool {
    let alive = peer.token.pidfd().is_none_or(|fd| !pidfd_exited(fd.as_raw_fd()));
    alive && ppid_start(peer.pid).is_ok_and(|(_, start)| start == peer.token.start)
}

/// A pidfd becomes readable when its process terminates.
fn pidfd_exited(fd: libc::c_int) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: `p` is one live pollfd and the count passed is 1; timeout 0
    // makes the call non-blocking.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    rc < 0 || p.revents & libc::POLLIN != 0
}

fn read(pid: u32, file: &str) -> Result<Vec<u8>, Error> {
    std::fs::read(format!("/proc/{pid}/{file}")).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::Gone,
        _ => Error::Os(e.raw_os_error().unwrap_or_else(errno)),
    })
}

pub(crate) fn exe(pid: u32) -> Result<PathBuf, Error> {
    std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::Gone,
        _ => Error::Os(e.raw_os_error().unwrap_or_else(errno)),
    })
}

/// (ppid, start time in clock ticks since boot).
pub(crate) fn ppid_start(pid: u32) -> Result<(u32, u64), Error> {
    parse::proc_stat(&read(pid, "stat")?).ok_or(Error::Malformed)
}

/// argv and env; unreadable (another user's, EACCES) means empty lists.
pub(crate) fn args(pid: u32) -> Result<(Vec<OsString>, Env), Error> {
    Ok((list(pid, "cmdline", parse::cmdline)?, list(pid, "environ", parse::environ)?))
}

fn list<T: Default>(pid: u32, file: &str, f: fn(&[u8]) -> T) -> Result<T, Error> {
    match read(pid, file) {
        Ok(buf) => {
            within_cap(buf.len())?;
            Ok(f(&buf))
        }
        Err(Error::Os(e)) if e == libc::EACCES || e == libc::EPERM => Ok(T::default()),
        Err(e) => Err(e),
    }
}

/// `PR_SET_DUMPABLE` is part of the agent's hardening, not this crate.
pub(crate) fn deny_attach() -> Result<(), Error> {
    Ok(())
}
