//! The two syscall shapes both OSes share, as safe functions over bytes.

use std::os::fd::RawFd;

use crate::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

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
