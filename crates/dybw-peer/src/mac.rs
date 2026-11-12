//! macOS: audit token, libproc, sysctl.

use std::ffi::OsString;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::parse::{self, Env};
use crate::raw::{cvt, errno, getsockopt, within_cap};
use crate::{Error, Peer, Token};

pub(crate) fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    let mut buf = [0u8; 32];
    let n = getsockopt(sock.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, &mut buf)?;
    let token = buf.get(..n).and_then(parse::audit_token);
    let (pid, uid, version) = token.ok_or(Error::Malformed)?;
    let (_, start) = ppid_start(pid)?;
    Ok(Peer { pid, uid, token: Token::new(version, start, None) })
}

pub(crate) fn still_same(peer: &Peer) -> bool {
    ppid_start(peer.pid).is_ok_and(|(_, start)| start == peer.token.start)
}

pub(crate) fn exe(pid: u32) -> Result<PathBuf, Error> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is valid for writes of its length, which is the size passed.
    let n = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let len = usize::try_from(n).unwrap_or(0);
    if len == 0 {
        return Err(Error::from_errno(errno()));
    }
    buf.truncate(len);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// (ppid, start time in microseconds since the epoch).
pub(crate) fn ppid_start(pid: u32) -> Result<(u32, u64), Error> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is valid for writes of `size` bytes, the size passed.
    let n =
        unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if n != size {
        return Err(Error::from_errno(errno()));
    }
    // SAFETY: the kernel filled all `size` bytes (checked above) of a plain
    // integer struct, and it was zero-initialised anyway.
    let info = unsafe { info.assume_init() };
    Ok((info.pbi_ppid, info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec))
}

/// argv and env through `KERN_PROCARGS2`. EINVAL/EPERM (another user's or a
/// zombie process) is not an error: the lists come back empty.
pub(crate) fn args(pid: u32) -> Result<(Vec<OsString>, Env), Error> {
    let buf = procargs(pid).or_else(|e| if tolerated(&e) { Ok(Vec::new()) } else { Err(e) })?;
    if buf.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    parse::procargs2(&buf).ok_or(Error::Malformed)
}

fn tolerated(e: &Error) -> bool {
    *e == Error::Os(libc::EINVAL) || *e == Error::Os(libc::EPERM)
}

fn procargs(pid: u32) -> Result<Vec<u8>, Error> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size = 0usize;
    sysctl(&mut mib, None, &mut size)?;
    within_cap(size)?;
    let mut buf = vec![0u8; size];
    sysctl(&mut mib, Some(&mut buf), &mut size)?;
    buf.truncate(size);
    Ok(buf)
}

/// `buf == None` asks for the size only.
fn sysctl(mib: &mut [libc::c_int; 3], buf: Option<&mut Vec<u8>>, size: &mut usize) -> Result<(), Error> {
    let ptr = buf.map_or(std::ptr::null_mut(), |b| b.as_mut_ptr().cast());
    // SAFETY: `mib` has the 3 entries announced; `ptr` is null (size query)
    // or valid for `*size` bytes, which the caller sized from the first call;
    // `size` is a live in/out length; no new value is set (null, 0).
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, ptr, size, std::ptr::null_mut(), 0) };
    cvt(rc)
}

pub(crate) fn deny_attach() -> Result<(), Error> {
    // SAFETY: PT_DENY_ATTACH takes no address and no data; it only flags the
    // calling process.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    cvt(rc)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn another_users_process_has_no_args_but_is_not_an_error() {
        // launchd belongs to root; the kernel refuses its arguments to us.
        let (argv, env) = args(1).unwrap();
        assert!(argv.is_empty() && env.is_empty());
    }

    #[test]
    fn a_missing_pid_has_no_path() {
        assert_eq!(exe(u32::MAX - 1), Err(Error::Gone));
        assert!(exe(std::process::id()).is_ok());
    }

    #[test]
    fn only_permission_errors_are_tolerated() {
        assert!(tolerated(&Error::Os(libc::EINVAL)) && tolerated(&Error::Os(libc::EPERM)));
        assert!(!tolerated(&Error::Os(libc::EIO)) && !tolerated(&Error::Gone));
    }

    #[test]
    fn own_args_include_the_test_binary() {
        let (argv, _) = args(std::process::id()).unwrap();
        assert!(!argv.is_empty());
    }
}
