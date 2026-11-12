//! macOS: audit token, libproc, sysctl.

use std::ffi::OsString;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::parse::{self, Env};
use crate::raw::{cvt, errno, getsockopt, within_cap};
use crate::{Error, Peer, Token};

/// `PROC_PIDUNIQIDENTIFIERINFO` (not in the libc crate).
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

/// `struct proc_uniqidentifierinfo` from `<sys/proc_info.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Uniq {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_reserve2: u32,
    p_reserve3: u64,
    p_reserve4: u64,
}

/// A libproc info struct that is plain integers: all-zero bytes are valid.
///
/// # Safety
/// Implement only for `repr(C)` types made of integers and integer arrays.
unsafe trait Pod: Copy {}
// SAFETY: integers only.
unsafe impl Pod for Uniq {}
// SAFETY: integers only.
unsafe impl Pod for libc::proc_bsdinfo {}

fn pidinfo<T: Pod>(pid: u32, flavor: libc::c_int) -> Result<T, Error> {
    let mut info = MaybeUninit::<T>::zeroed();
    let size = size_of::<T>() as libc::c_int;
    // SAFETY: `info` is valid for writes of `size` bytes, the size passed.
    let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, flavor, 0, info.as_mut_ptr().cast(), size) };
    if n != size {
        return Err(Error::from_errno(errno()));
    }
    // SAFETY: the kernel filled all `size` bytes (checked above) and `T: Pod`
    // makes every bit pattern valid (it was zero-initialised anyway).
    Ok(unsafe { info.assume_init() })
}

fn uniq(pid: u32) -> Result<Uniq, Error> {
    pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO)
}

pub(crate) fn peer_of(sock: BorrowedFd<'_>) -> Result<Peer, Error> {
    let mut buf = [0u8; 32];
    let n = getsockopt(sock.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, &mut buf)?;
    let token = buf.get(..n).and_then(parse::audit_token);
    let (pid, uid, version) = token.ok_or(Error::Malformed)?;
    peer_from(pid, uid, version)
}

/// The audit token's pidversion must still be the pid's current one: a pid
/// reused, or exec'd, since connect has another.
fn version_matches(idversion: i32, version: u32) -> Result<(), Error> {
    if idversion as u32 == version { Ok(()) } else { Err(Error::Gone) }
}

fn peer_from(pid: u32, uid: u32, version: u32) -> Result<Peer, Error> {
    version_matches(uniq(pid)?.p_idversion, version)?;
    let (_, start, image) = crate::stable_id(pid)?;
    Ok(Peer { pid, uid, token: Token::new(version, start, image, None) })
}

#[cfg(test)]
pub(crate) fn peer_of_pid(pid: u32) -> Result<Peer, Error> {
    peer_from(pid, 0, uniq(pid)?.p_idversion as u32)
}

/// The kernel's unique id (never reused), pidversion (bumped by exec) and the
/// executable's UUID.
pub(crate) fn image(pid: u32) -> Result<Vec<u8>, Error> {
    let u = uniq(pid)?;
    let mut image = u.p_uniqueid.to_ne_bytes().to_vec();
    image.extend(u.p_idversion.to_ne_bytes());
    image.extend(u.p_uuid);
    Ok(image)
}

/// Nothing to add to the identity re-check on macOS.
pub(crate) fn alive(_peer: &Peer) -> bool {
    true
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
    let info: libc::proc_bsdinfo = pidinfo(pid, libc::PROC_PIDTBSDINFO)?;
    Ok((info.pbi_ppid, info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec))
}

/// argv and env through `KERN_PROCARGS2`. EINVAL/EPERM (another user's, a
/// SIP-protected or a zombie process) means "not visible": both `None`.
pub(crate) fn args(pid: u32) -> Result<(Option<Vec<OsString>>, Option<Env>), Error> {
    let buf = procargs(pid).map(Some).or_else(|e| if tolerated(&e) { Ok(None) } else { Err(e) })?;
    let Some(buf) = buf else {
        return Ok((None, None));
    };
    let (argv, env) = parse::procargs2(&buf).ok_or(Error::Malformed)?;
    Ok((Some(argv), Some(env)))
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
    use std::process::{Command, Stdio};

    #[test]
    fn another_users_process_has_no_visible_args() {
        // launchd belongs to root; the kernel refuses its arguments to us.
        assert_eq!(args(1).unwrap(), (None, None));
        // and a pid that cannot exist is not "visible but empty" either.
        assert_eq!(args(u32::MAX - 1).unwrap(), (None, None));
    }

    #[test]
    fn a_stale_audit_token_version_is_gone() {
        let me = std::process::id();
        let current = uniq(me).unwrap().p_idversion;
        assert_eq!(version_matches(current, current as u32), Ok(()));
        assert_eq!(peer_from(me, 0, current as u32 + 1).err(), Some(Error::Gone));
        assert!(peer_from(me, 0, current as u32).is_ok());
    }

    #[test]
    fn exec_changes_the_image() {
        let mut child =
            Command::new("/bin/sh").args(["-c", "read x; exec /bin/sleep 30"]).stdin(Stdio::piped()).spawn().unwrap();
        let before = image(child.id()).unwrap();
        drop(child.stdin.take());
        while image(child.id()).unwrap() == before {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn only_permission_errors_are_tolerated() {
        assert!(tolerated(&Error::Os(libc::EINVAL)) && tolerated(&Error::Os(libc::EPERM)));
        assert!(!tolerated(&Error::Os(libc::EIO)) && !tolerated(&Error::Gone));
    }

    #[test]
    fn a_missing_pid_has_no_path() {
        assert_eq!(exe(u32::MAX - 1), Err(Error::Gone));
        assert!(exe(std::process::id()).is_ok());
    }

    #[test]
    fn own_args_include_the_test_binary() {
        let (argv, env) = args(std::process::id()).unwrap();
        assert!(!argv.unwrap().is_empty() && env.is_some());
    }
}
