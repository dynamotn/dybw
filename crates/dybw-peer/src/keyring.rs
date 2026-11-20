//! The user's kernel keyring (`@u`, keyctl), where `pam_bwss` hands the login password to the agent (ADR 0006): a
//! `user` key per entry, readable by its user only, gone after 60 s. Linux only.
//!
//! [`take`] does the consumer's three steps: search `@u` for the description, read the payload, and invalidate the
//! key at once, whether the read worked or not.

use zeroize::Zeroizing;

use crate::Error;

/// The largest payload of a `user` key.
const MAX_PAYLOAD: usize = 32767;

fn keyctl(op: u32, a: libc::c_long, b: libc::c_long, c: libc::c_long, d: libc::c_long) -> Result<libc::c_long, Error> {
    // SAFETY: every caller passes integers, or pointers to memory that outlives the call with the length it names.
    let r = unsafe { libc::syscall(libc::SYS_keyctl, libc::c_long::from(op), a, b, c, d) };
    if r < 0 { Err(Error::Os(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))) } else { Ok(r) }
}

/// The id of the `user` key `name` in `@u`; `None` when there is none, or only an expired or revoked one.
fn search(name: &std::ffi::CStr) -> Result<Option<libc::c_long>, Error> {
    let kind = c"user";
    let found = keyctl(
        libc::KEYCTL_SEARCH,
        libc::c_long::from(libc::KEY_SPEC_USER_KEYRING),
        kind.as_ptr() as libc::c_long,
        name.as_ptr() as libc::c_long,
        0,
    );
    match found {
        Err(Error::Os(libc::ENOKEY | libc::EKEYEXPIRED | libc::EKEYREVOKED)) => Ok(None),
        other => other.map(Some),
    }
}

/// Take the entry `name` from the user keyring: its payload, and the key invalidated. `None` when there is none.
pub fn take(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let name = std::ffi::CString::new(name).map_err(|_| Error::Malformed)?;
    let Some(id) = search(&name)? else { return Ok(None) };
    let mut buf = Zeroizing::new(vec![0u8; MAX_PAYLOAD]);
    let read = keyctl(libc::KEYCTL_READ, id, buf.as_mut_ptr() as libc::c_long, MAX_PAYLOAD as libc::c_long, 0);
    // Invalidated whatever the read gave: an entry is read once.
    let gone = keyctl(libc::KEYCTL_INVALIDATE, id, 0, 0, 0);
    let len = usize::try_from(read?).map_err(|_| Error::Malformed)?;
    gone?;
    buf.truncate(len.min(MAX_PAYLOAD));
    Ok(Some(buf))
}

/// Whether this process may search the user keyring (`dybw doctor`): a sandbox's seccomp filter or a kernel without
/// keys refuses it.
pub fn readable() -> Result<(), Error> {
    search(c"dybw:doctor-probe").map(|_| ())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// What `pam_bwss` does: a `user` key made in a fresh session keyring (so it is possessed while it is linked into
    /// `@u`), then given pam_bwss's permissions (possessor and user: view, read, search) and unlinked from the
    /// session, so the reader holds it by its user permissions only, as the agent may.
    fn add(name: &str, payload: &[u8]) {
        let (kind, name) = (c"user", std::ffi::CString::new(name).unwrap());
        let session = libc::c_long::from(libc::KEY_SPEC_SESSION_KEYRING);
        let user = libc::c_long::from(libc::KEY_SPEC_USER_KEYRING);
        keyctl(libc::KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0).unwrap();
        // SAFETY: the strings and the payload outlive the call, and the length is the payload's.
        let id = unsafe {
            libc::syscall(libc::SYS_add_key, kind.as_ptr(), name.as_ptr(), payload.as_ptr(), payload.len(), session)
        };
        assert!(id > 0, "add_key: {}", std::io::Error::last_os_error());
        keyctl(libc::KEYCTL_LINK, id, user, 0, 0).unwrap();
        keyctl(libc::KEYCTL_SETPERM, id, 0x0b0b_0000, 0, 0).unwrap();
        keyctl(libc::KEYCTL_UNLINK, id, session, 0, 0).unwrap();
    }

    #[test]
    fn an_entry_is_read_once_then_gone() {
        let name = format!("dybw:test-{}", std::process::id());
        assert_eq!(take(&name).unwrap(), None);
        add(&name, b"pass word\x00\xff");
        assert_eq!(take(&name).unwrap().as_deref().map(Vec::as_slice), Some(&b"pass word\x00\xff"[..]));
        assert_eq!(take(&name).unwrap(), None, "invalidated after the read");
        readable().unwrap();
    }

    #[test]
    fn a_name_with_a_nul_or_a_failed_call_is_an_error() {
        assert_eq!(take("a\0b"), Err(Error::Malformed));
        assert!(matches!(keyctl(libc::KEYCTL_INVALIDATE, 0, 0, 0, 0), Err(Error::Os(_))));
    }
}
