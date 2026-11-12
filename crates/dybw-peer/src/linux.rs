//! Linux: SO_PEERCRED / SO_PEERPIDFD and /proc.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use crate::parse::{self, Env};
use crate::raw::{errno, getsockopt, within_cap};
use crate::{Error, MAX_ARGS_BYTES, Peer, Token};

/// `SO_PEERPIDFD` (kernel 6.5+): 77 on the architectures that share the
/// generic socket ABI. Others (mips, powerpc, sparc, alpha, parisc) have
/// other numbers, so the pidfd is not asked for there and the start time
/// and image carry the identity.
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "loongarch64"
))]
const SO_PEERPIDFD: Option<libc::c_int> = Some(77);
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "loongarch64"
)))]
const SO_PEERPIDFD: Option<libc::c_int> = None;

pub(crate) fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 12];
    let n = getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut buf)?;
    let (pid, uid) = buf.get(..n).and_then(parse::ucred).ok_or(Error::Malformed)?;
    peer_from(pid, uid, peer_pidfd(fd))
}

/// With a pidfd, the descriptor must name the same pid SO_PEERCRED gave.
fn peer_from(pid: u32, uid: u32, pidfd: Option<OwnedFd>) -> Result<Peer, Error> {
    if let Some(fd) = &pidfd {
        pidfd_names(fd, pid)?;
    }
    let (_, start, image) = crate::stable_id(pid)?;
    Ok(Peer { pid, uid, token: Token::new(0, start, image, pidfd) })
}

#[cfg(test)]
pub(crate) fn peer_of_pid(pid: u32) -> Result<Peer, Error> {
    peer_from(pid, 0, None)
}

fn pidfd_names(fd: &OwnedFd, pid: u32) -> Result<(), Error> {
    let buf = std::fs::read(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).map_err(io_err)?;
    if parse::pidfd_pid(&buf) == Some(i64::from(pid)) { Ok(()) } else { Err(Error::Gone) }
}

/// The pidfd of the peer, or `None` on a kernel (or architecture) without
/// `SO_PEERPIDFD`: the start time and image then carry the identity alone.
fn peer_pidfd(fd: libc::c_int) -> Option<OwnedFd> {
    let mut buf = [0u8; 4];
    let n = getsockopt(fd, libc::SOL_SOCKET, SO_PEERPIDFD?, &mut buf).ok()?;
    let raw = i32::from_ne_bytes(buf);
    // 0, 1 and 2 would be the standard streams, not a fresh descriptor.
    if n != 4 || raw <= 2 {
        return None;
    }
    // SAFETY: on success the kernel installed a new descriptor (> 2) in this
    // process for the pidfd and nothing else owns it; it is closed once, by
    // the OwnedFd.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The pidfd, when held, must not have become readable (process exited).
pub(crate) fn alive(peer: &Peer) -> bool {
    peer.token.pidfd().is_none_or(|fd| !pidfd_exited(fd.as_raw_fd()))
}

/// A pidfd becomes readable when its process terminates.
fn pidfd_exited(fd: libc::c_int) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: `p` is one live pollfd and the count passed is 1; timeout 0
    // makes the call non-blocking.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    rc < 0 || p.revents & libc::POLLIN != 0
}

fn io_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::NotFound => Error::Gone,
        _ => Error::Os(e.raw_os_error().unwrap_or_else(errno)),
    }
}

/// Read at most `MAX_ARGS_BYTES` of a /proc file; more is `TooLarge`.
fn read(pid: u32, file: &str) -> Result<Vec<u8>, Error> {
    let f = std::fs::File::open(format!("/proc/{pid}/{file}")).map_err(io_err)?;
    let mut buf = Vec::new();
    f.take(MAX_ARGS_BYTES as u64 + 1).read_to_end(&mut buf).map_err(io_err)?;
    within_cap(buf.len())?;
    Ok(buf)
}

pub(crate) fn exe(pid: u32) -> Result<PathBuf, Error> {
    std::fs::read_link(format!("/proc/{pid}/exe")).map_err(io_err)
}

/// The exe link target plus the (dev, ino) of the file behind it: changes
/// when the process execs another program, or the file is replaced.
pub(crate) fn image(pid: u32) -> Result<Vec<u8>, Error> {
    let md = std::fs::metadata(format!("/proc/{pid}/exe")).map_err(io_err)?;
    let mut image = md.dev().to_ne_bytes().to_vec();
    image.extend(md.ino().to_ne_bytes());
    image.extend(exe(pid)?.as_os_str().as_bytes());
    Ok(image)
}

/// (ppid, start time in clock ticks since boot).
pub(crate) fn ppid_start(pid: u32) -> Result<(u32, u64), Error> {
    parse::proc_stat(&read(pid, "stat")?).ok_or(Error::Malformed)
}

/// argv and env; unreadable (another user's: EACCES/EPERM) is `None`.
pub(crate) fn args(pid: u32) -> Result<(Option<Vec<OsString>>, Option<Env>), Error> {
    Ok((list(pid, "cmdline", parse::cmdline)?, list(pid, "environ", parse::environ)?))
}

fn list<T>(pid: u32, file: &str, f: fn(&[u8]) -> T) -> Result<Option<T>, Error> {
    match read(pid, file) {
        Ok(buf) => Ok(Some(f(&buf))),
        Err(Error::Os(e)) if e == libc::EACCES || e == libc::EPERM => Ok(None),
        Err(e) => Err(e),
    }
}

/// The start time (clock ticks since boot, 100 per second: USER_HZ is fixed for userspace) as a wall-clock time,
/// from the boot time in `/proc/stat`; `None` when that cannot be read.
pub(crate) fn started(start: u64) -> Option<std::time::SystemTime> {
    let mut buf = Vec::new();
    std::fs::File::open("/proc/stat").ok()?.take(MAX_ARGS_BYTES as u64).read_to_end(&mut buf).ok()?;
    let boot = parse::btime(&buf)?;
    std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_millis(boot * 1000 + start * 10))
}

/// The working directory; another user's (EACCES/EPERM) is `None`.
pub(crate) fn cwd(pid: u32) -> Result<Option<PathBuf>, Error> {
    match std::fs::read_link(format!("/proc/{pid}/cwd")) {
        Ok(p) => Ok(Some(p)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM | libc::EINVAL)) => Ok(None),
        Err(e) => Err(io_err(e)),
    }
}

/// `PR_SET_DUMPABLE` is part of the agent's hardening, not this crate.
pub(crate) fn deny_attach() -> Result<(), Error> {
    Ok(())
}
