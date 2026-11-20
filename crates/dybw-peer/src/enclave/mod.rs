//! The Secure Enclave and Touch ID (macOS), for the `biometric` protector and the agent's confirmations (ADR 0006
//! "Touch ID on macOS").
//!
//! A key made by [`create`] lives in the Secure Enclave; what is kept on disk is its `dataRepresentation`, a handle
//! only that Mac's enclave can use (no keychain item, so no entitlement). [`wrap`] agrees an ephemeral P-256 key
//! with its public half without asking anything; [`derive`] gets the same 32 bytes back after Touch ID. Those bytes
//! are the core's `Kek::Hardware` input. The scheme (ECDH + HKDF-SHA256, info `dybw-unlock:biometric-se` with both
//! public keys) is in `secure_enclave.swift`.
//!
//! Other systems have no enclave: everything answers [`Error::Unavailable`].

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
use mac as sys;

/// A public key, X9.63 uncompressed (`04 || x || y`).
pub type PublicKey = [u8; 65];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// No Secure Enclave, no Touch ID sensor (or the lid is closed), no finger enrolled, or no login password.
    #[error("Touch ID or the Secure Enclave is not available")]
    Unavailable,
    /// The user (or the system) dismissed the Touch ID sheet.
    #[error("Touch ID was cancelled")]
    Cancelled,
    /// The finger did not match.
    #[error("Touch ID did not recognise the finger")]
    Failed,
    /// Too many failed matches: Touch ID waits for the login password.
    #[error("Touch ID is locked out")]
    LockedOut,
    /// The key no longer works: the enrolled fingers changed (`biometryCurrentSet`), or the handle is not this Mac's.
    #[error("the Secure Enclave key no longer works")]
    Invalidated,
    /// Anything else, with the raw error code macOS gave (`-34018`: a missing entitlement).
    #[error("the Secure Enclave call failed (code {0})")]
    Other(i64),
}

/// Which enrolled fingers open the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// The fingers enrolled now: adding or removing one makes the key unusable (the default).
    CurrentSet,
    /// Any finger enrolled at the time of use: survives changes, weaker.
    Any,
}

/// A new Secure Enclave key.
#[derive(Debug, Clone)]
pub struct Created {
    /// The `dataRepresentation`: the handle to keep; usable only by this Mac's enclave.
    pub handle: Vec<u8>,
    pub public: PublicKey,
}

/// The wrapping side's result: keep `ephemeral` with the blob, use `secret` as the KEK input.
#[derive(Debug)]
pub struct Wrapped {
    pub ephemeral: PublicKey,
    pub secret: Zeroizing<[u8; 32]>,
}

/// The answer to a Touch ID confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Allowed,
    /// The finger did not match.
    Denied,
    /// Ask the same question through pinentry instead.
    Unavailable,
    Cancelled,
}

/// Whether this Mac has a Secure Enclave.
pub fn available() -> bool {
    sys::available()
}

/// A new P-256 key in the Secure Enclave, usable only while the Mac is unlocked and after Touch ID by `policy`
/// (`watch`: or an Apple Watch). Creating it asks nothing.
pub fn create(policy: Policy, watch: bool) -> Result<Created, Error> {
    sys::create(policy == Policy::Any, watch)
}

/// The wrapping side, without Touch ID: 32 bytes only `derive` with the key behind `public` can find again.
pub fn wrap(public: &PublicKey) -> Result<Wrapped, Error> {
    sys::wrap(public)
}

/// The unwrapping side: shows the Touch ID sheet with `reason` (every call asks), then returns [`wrap`]'s secret.
pub fn derive(handle: &[u8], ephemeral: &PublicKey, reason: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    sys::derive(handle, ephemeral, &c_reason(reason))
}

/// A yes or no by Touch ID; blocks the calling thread, which must not be a main run loop thread.
pub fn confirm(reason: &str) -> Confirm {
    confirmation(sys::confirm(&c_reason(reason)))
}

fn c_reason(reason: &str) -> std::ffi::CString {
    std::ffi::CString::new(reason.replace('\0', "")).unwrap_or_default()
}

/// Touch ID decides only a match; anything that is not a match or a cancel goes to pinentry (ADR 0006).
fn confirmation(result: Result<(), Error>) -> Confirm {
    match result {
        Ok(()) => Confirm::Allowed,
        Err(Error::Failed) => Confirm::Denied,
        Err(Error::Cancelled) => Confirm::Cancelled,
        Err(_) => Confirm::Unavailable,
    }
}

/// The shim's status codes (`secure_enclave.swift`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn status(code: i32, detail: i64) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        1 => Err(Error::Unavailable),
        2 => Err(Error::Cancelled),
        3 => Err(Error::Failed),
        4 => Err(Error::LockedOut),
        5 => Err(Error::Invalidated),
        _ => Err(Error::Other(detail)),
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    use super::{Created, Error, PublicKey, Wrapped, Zeroizing};
    use std::ffi::CStr;

    pub(super) fn available() -> bool {
        false
    }

    pub(super) fn create(_any: bool, _watch: bool) -> Result<Created, Error> {
        Err(Error::Unavailable)
    }

    pub(super) fn wrap(_public: &PublicKey) -> Result<Wrapped, Error> {
        Err(Error::Unavailable)
    }

    pub(super) fn derive(_handle: &[u8], _ephemeral: &PublicKey, _reason: &CStr) -> Result<Zeroizing<[u8; 32]>, Error> {
        Err(Error::Unavailable)
    }

    pub(super) fn confirm(_reason: &CStr) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_map_to_errors() {
        let table = [
            (1, Error::Unavailable),
            (2, Error::Cancelled),
            (3, Error::Failed),
            (4, Error::LockedOut),
            (5, Error::Invalidated),
            (6, Error::Other(-34018)),
            (99, Error::Other(-34018)),
        ];
        assert_eq!(status(0, 7), Ok(()));
        for (code, error) in table {
            assert_eq!(status(code, -34018), Err(error), "{code}");
        }
    }

    #[test]
    fn only_a_match_allows_and_only_a_mismatch_denies() {
        assert_eq!(confirmation(Ok(())), Confirm::Allowed);
        assert_eq!(confirmation(Err(Error::Failed)), Confirm::Denied);
        assert_eq!(confirmation(Err(Error::Cancelled)), Confirm::Cancelled);
        for error in [Error::Unavailable, Error::LockedOut, Error::Invalidated, Error::Other(-1)] {
            assert_eq!(confirmation(Err(error)), Confirm::Unavailable, "{error}");
        }
    }

    #[test]
    fn a_reason_with_a_nul_still_reaches_the_sheet() {
        assert_eq!(c_reason("Unlock\0 dybw").to_bytes(), b"Unlock dybw");
    }

    /// No test asks for Touch ID or needs an enclave: CI's macOS runner has none.
    #[test]
    fn a_garbage_handle_or_public_key_is_refused_without_a_prompt() {
        let garbage = [0x5a; 65];
        assert!(derive(b"not a handle", &garbage, "test").is_err());
        assert!(wrap(&garbage).is_err());
    }

    #[test]
    fn creating_a_key_works_or_says_why() {
        // An enclave key held only by its handle is not stored anywhere: nothing to clean up.
        let here = available();
        let created = create(Policy::CurrentSet, false);
        assert!(created.as_ref().map_or_else(|e| !here || matches!(e, Error::Other(_)), |c| here && c.public[0] == 4));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_systems_have_no_enclave() {
        assert!(!available());
        assert_eq!(create(Policy::Any, true).err(), Some(Error::Unavailable));
        assert_eq!(confirm("test"), Confirm::Unavailable);
    }
}
