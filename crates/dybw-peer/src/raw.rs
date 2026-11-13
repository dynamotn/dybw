//! The two syscall shapes both OSes share, as safe functions over bytes.

use std::ffi::{CStr, OsStr};
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::Error;

/// Largest buffer offered to `getpwuid_r`: an entry that needs more is not believed.
const MAX_PASSWD_BUF: usize = 1 << 20;

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Turn a C return code of 0-on-success into a `Result`.
pub(crate) fn cvt(rc: libc::c_int) -> Result<(), Error> {
    if rc == 0 { Ok(()) } else { Err(Error::from_errno(errno())) }
}

/// Refuse to read an argument block past [`crate::MAX_ARGS_BYTES`].
pub(crate) fn within_cap(size: usize) -> Result<(), Error> {
    if size > crate::MAX_ARGS_BYTES { Err(Error::TooLarge) } else { Ok(()) }
}

/// `getsockopt` into a caller buffer; returns how many bytes the kernel wrote.
pub(crate) fn getsockopt(fd: RawFd, level: libc::c_int, name: libc::c_int, buf: &mut [u8]) -> Result<usize, Error> {
    let mut len = libc::socklen_t::try_from(buf.len()).unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `buf` is valid for writes of `len` bytes and `len` is a live
    // socklen_t the kernel updates; nothing is retained after the call.
    let rc = unsafe { libc::getsockopt(fd, level, name, buf.as_mut_ptr().cast(), &mut len) };
    cvt(rc)?;
    Ok((len as usize).min(buf.len()))
}

/// The home directory of `uid` in the password database, starting with a `start`-byte buffer and doubling it while
/// the entry does not fit. `None`: no entry, an error, or a home that is not an absolute path.
pub(crate) fn home_of(uid: u32, start: usize) -> Option<PathBuf> {
    let mut size = start.max(1);
    loop {
        let mut buf = vec![0u8; size];
        let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd` is valid for one `passwd`, `buf` for `buf.len()` bytes, `out` is a live pointer slot; the
        // strings the call stores in `pwd` point into `buf`, which outlives every read below.
        let rc = unsafe { libc::getpwuid_r(uid, pwd.as_mut_ptr(), buf.as_mut_ptr().cast(), buf.len(), &mut out) };
        if rc == libc::ERANGE && size < MAX_PASSWD_BUF {
            size *= 2;
            continue;
        }
        if rc != 0 || out.is_null() {
            return None;
        }
        // SAFETY: on success `out` points at `pwd`, which the call filled in.
        let dir = unsafe { (*out).pw_dir };
        if dir.is_null() {
            return None;
        }
        // SAFETY: `pw_dir` is a NUL-terminated string inside `buf`, still alive and unchanged.
        let bytes = unsafe { CStr::from_ptr(dir) }.to_bytes();
        let home = PathBuf::from(OsStr::from_bytes(bytes));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn the_home_of_a_user_comes_from_the_password_database() {
        let root = home_of(0, 1024).unwrap();
        assert_eq!(root, PathBuf::from(if cfg!(target_os = "macos") { "/var/root" } else { "/root" }));
        // A one-byte buffer grows until the entry fits.
        assert_eq!(home_of(0, 1), Some(root));
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = home_of(unsafe { libc::geteuid() }, 1024).unwrap();
        assert!(me.is_absolute());
        assert_eq!(home_of(4_000_000_000, 1024), None, "no such user");
    }

    #[test]
    fn failures_carry_errno() {
        let mut buf = [0u8; 4];
        assert_eq!(getsockopt(-1, libc::SOL_SOCKET, libc::SO_TYPE, &mut buf), Err(Error::Os(libc::EBADF)));
        assert_eq!(cvt(0), Ok(()));
        assert_eq!(within_cap(crate::MAX_ARGS_BYTES), Ok(()));
        assert_eq!(within_cap(crate::MAX_ARGS_BYTES + 1), Err(Error::TooLarge));
        assert!(cvt(-1).is_err());
    }
}
