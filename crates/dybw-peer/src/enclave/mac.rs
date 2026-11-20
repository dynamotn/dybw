//! macOS: the Swift shim's C ABI (`secure_enclave.swift`, built by build.rs). Every buffer is ours, of the size the
//! shim is told or documents (65 bytes for a public key, 32 for a secret).

use std::ffi::{CStr, c_char};

use zeroize::Zeroizing;

use super::{Created, Error, PublicKey, Wrapped, status};

/// More than a Secure Enclave `dataRepresentation` takes (a few hundred bytes).
const HANDLE_CAP: usize = 4096;

unsafe extern "C" {
    fn dybw_se_available() -> bool;
    fn dybw_se_create(
        any: bool,
        watch: bool,
        data: *mut u8,
        data_cap: isize,
        data_len: *mut isize,
        public: *mut u8,
        detail: *mut i64,
    ) -> i32;
    fn dybw_se_wrap(enclave: *const u8, ephemeral: *mut u8, out: *mut u8, detail: *mut i64) -> i32;
    fn dybw_se_derive(
        data: *const u8,
        data_len: isize,
        ephemeral: *const u8,
        reason: *const c_char,
        out: *mut u8,
        detail: *mut i64,
    ) -> i32;
    fn dybw_la_confirm(reason: *const c_char, detail: *mut i64) -> i32;
    #[cfg(test)]
    fn dybw_se_test_derive(scalar: *const u8, ephemeral: *const u8, public: *mut u8, out: *mut u8) -> i32;
}

pub(super) fn available() -> bool {
    // SAFETY: no arguments; the shim reads `SecureEnclave.isAvailable`.
    unsafe { dybw_se_available() }
}

pub(super) fn create(any: bool, watch: bool) -> Result<Created, Error> {
    let mut handle = vec![0u8; HANDLE_CAP];
    let mut len: isize = 0;
    let mut public = [0u8; 65];
    let mut detail = 0i64;
    // SAFETY: `handle` has HANDLE_CAP writable bytes and the shim writes at most `data_cap`; `public` has the 65 bytes
    // the shim writes; `len` and `detail` are valid for one write each.
    let code = unsafe {
        dybw_se_create(any, watch, handle.as_mut_ptr(), HANDLE_CAP as isize, &mut len, public.as_mut_ptr(), &mut detail)
    };
    status(code, detail)?;
    handle.truncate(usize::try_from(len).unwrap_or(0));
    Ok(Created { handle, public })
}

pub(super) fn wrap(public: &PublicKey) -> Result<Wrapped, Error> {
    let mut ephemeral = [0u8; 65];
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut detail = 0i64;
    // SAFETY: `public` is 65 readable bytes, `ephemeral` 65 and `secret` 32 writable ones, `detail` one i64.
    let code = unsafe { dybw_se_wrap(public.as_ptr(), ephemeral.as_mut_ptr(), secret.as_mut_ptr(), &mut detail) };
    status(code, detail).map(|()| Wrapped { ephemeral, secret })
}

pub(super) fn derive(handle: &[u8], ephemeral: &PublicKey, reason: &CStr) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut detail = 0i64;
    let len = isize::try_from(handle.len()).map_err(|_| Error::Other(0))?;
    // SAFETY: `handle` is `len` readable bytes, `ephemeral` 65, `reason` a NUL-terminated string living past the
    // call, `secret` 32 writable bytes, `detail` one i64. The call blocks until Touch ID answers.
    let code = unsafe {
        dybw_se_derive(handle.as_ptr(), len, ephemeral.as_ptr(), reason.as_ptr(), secret.as_mut_ptr(), &mut detail)
    };
    status(code, detail).map(|()| secret)
}

pub(super) fn confirm(reason: &CStr) -> Result<(), Error> {
    let mut detail = 0i64;
    // SAFETY: `reason` is NUL-terminated and outlives the blocking call; `detail` is one writable i64.
    let code = unsafe { dybw_la_confirm(reason.as_ptr(), &mut detail) };
    status(code, detail)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// The unwrapping side with a software key: the shim's test hook, same ECDH and HKDF as `dybw_se_derive`.
    /// Returns the key's public half, and the secret when `ephemeral` is a valid point.
    fn soft(scalar: &[u8; 32], ephemeral: &PublicKey) -> (PublicKey, Option<[u8; 32]>) {
        let (mut public, mut out) = ([0u8; 65], [0u8; 32]);
        // SAFETY: 32 and 65 readable bytes in, 65 and 32 writable bytes out.
        let code =
            unsafe { dybw_se_test_derive(scalar.as_ptr(), ephemeral.as_ptr(), public.as_mut_ptr(), out.as_mut_ptr()) };
        (public, (code == 0).then_some(out))
    }

    #[test]
    fn the_wrapped_secret_comes_back_from_the_matching_key_only() {
        let (public, none) = soft(&[0x11; 32], &[0; 65]);
        assert_eq!(none, None);
        let wrapped = wrap(&public).expect("a valid public key wraps");
        assert_eq!(wrapped.ephemeral[0], 4);
        assert_eq!(soft(&[0x11; 32], &wrapped.ephemeral).1, Some(*wrapped.secret));
        assert_ne!(soft(&[0x33; 32], &wrapped.ephemeral).1, Some(*wrapped.secret));
        // A fresh ephemeral key each time: two wraps never share a secret.
        assert_ne!(*wrap(&public).expect("wraps").secret, *wrapped.secret);
    }

    /// Pins the HKDF salt and info: changing them would strand every enrolled blob.
    #[test]
    fn the_derivation_is_a_known_answer() {
        let (ephemeral, _) = soft(&[0x22; 32], &[0; 65]);
        let (_, secret) = soft(&[0x11; 32], &ephemeral);
        let hex: String = secret.expect("derives").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, KNOWN);
    }

    /// Cross-checked with Python `cryptography` (ECDH, then HKDF-SHA256 with the same salt and info).
    const KNOWN: &str = "f5e9a126c90c923394c2723b32656db21c7b4acc823cdfd4c0b5b3cbce48d5e9";
}
