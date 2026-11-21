//! The `biometric` protector (ADR 0006 "Touch ID on macOS"): a copy of the user key wrapped by 32 bytes only this
//! Mac's Secure Enclave gives back after Touch ID. On disk at `<state>/unlock/biometric` (0600, its directory 0700,
//! written whole): the core's protector blob (bound to the device), the enclave key's `dataRepresentation` (a handle
//! no other Mac can use) and the ephemeral public key of the wrap. Enrolment is in [`super::pin`] and asks no Touch ID.
//!
//! An unlock shows the Touch ID sheet, whose reason names the profile; every unlock asks. A cancel, an unavailable
//! sensor (lid closed, none enrolled), a failed match, a lockout or any other enclave error go on to the PIN or the
//! master password and keep the protector (an unknown error is logged with its code). A key the enclave no longer
//! opens (the enrolled fingers changed, `biometryCurrentSet`), a blob that does not fit this device or account, and
//! a key the account refuses delete it, logged and audited (`unlock-biometric-dropped`); enrolling again needs the
//! master password.

use dybw_core::crypto::SymmetricKey;
use dybw_core::profile::protector::{self, Binding, Kek, KekSource, Protector, ProtectorBlob, ProtectorError};
use dybw_native::fsutil::{ensure_private_dir, write_private};
use dybw_native::ports::kdf::BlockingArgon2;
use dybw_native::ports::random::OsRandom;
use dybw_peer::enclave::{self, Policy, PublicKey};
use serde::{Deserialize, Serialize};

use super::pin::{audit_as, binding};
use crate::caller::Caller;
use crate::host::Host;
use crate::policy::Verdict;
use crate::session::{self, Ctx, Session};

/// The protector's name, and its file under `<state>/unlock`.
pub(crate) const BIOMETRIC: &str = "biometric";

/// The file: the blob, the enclave key's handle and the wrap's ephemeral public key (X9.63, 65 bytes).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    protector: ProtectorBlob,
    handle: Vec<u8>,
    ephemeral: Vec<u8>,
}

fn path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.paths.unlock.join(BIOMETRIC)
}

/// Whether the profile has a `biometric` protector on this device.
pub(super) fn enrolled(ctx: &Ctx) -> bool {
    path(ctx).exists()
}

/// Delete the protector: whether there was one. The enclave key needs no cleanup: its handle was only in the file.
pub(super) fn delete(ctx: &Ctx) -> bool {
    std::fs::remove_file(path(ctx)).is_ok()
}

/// [`delete`], saying why in the log and the audit (`unlock-biometric-dropped`).
pub(super) fn drop_biometric(ctx: &Ctx, caller: &Caller, why: &str) {
    if delete(ctx) {
        tracing::warn!(profile = %ctx.profile.name, "the biometric protector was dropped: {why}");
        audit_as(ctx, caller, BIOMETRIC, "unlock-biometric-dropped", Verdict::Failed);
    }
}

/// A stored protector: the blob, the enclave key's handle, the wrap's ephemeral public key.
type Opened = (ProtectorBlob, Vec<u8>, PublicKey);

/// The stored protector: `None` when there is none; an error when it cannot be read as one.
fn read(ctx: &Ctx) -> Option<Result<Opened, ProtectorError>> {
    let raw = std::fs::read(path(ctx)).ok()?;
    let stored = serde_json::from_slice::<Stored>(&raw).map_err(|_| ProtectorError::Format);
    Some(stored.and_then(|s| {
        let ephemeral = PublicKey::try_from(s.ephemeral.as_slice()).map_err(|_| ProtectorError::Format)?;
        let kind = s.protector.protector();
        if kind == Protector::Biometric { Ok((s.protector, s.handle, ephemeral)) } else { Err(ProtectorError::Format) }
    }))
}

/// Make the enclave key, wrap `user` for it (no Touch ID) and write the file. `any`: any finger enrolled at the
/// time of use (`biometryAny`), else only today's; `watch`: an Apple Watch too. The error is for the log.
pub(super) async fn enrol<H: Host>(
    host: &H,
    ctx: &Ctx,
    user: &SymmetricKey,
    (device, machine): (&str, &str),
    any: bool,
    watch: bool,
) -> Result<(), String> {
    let policy = if any { Policy::Any } else { Policy::CurrentSet };
    let made = host.enclave_create(policy, watch).and_then(|c| host.enclave_wrap(&c.public).map(|w| (c, w)));
    let (created, wrapped) = made.map_err(|e| e.to_string())?;
    let source = KekSource::Hardware(wrapped.secret);
    let bound = Binding { device_id: device, machine };
    let blob = protector::wrap(user, Protector::Biometric, source, bound, &BlockingArgon2, &OsRandom)
        .await
        .map_err(|e| e.code().to_owned())?;
    let stored = Stored { protector: blob, handle: created.handle, ephemeral: wrapped.ephemeral.to_vec() };
    // Byte lists and the blob's strings: serializing cannot fail.
    let json = serde_json::to_vec(&stored).unwrap_or_default();
    ensure_private_dir(&ctx.paths.unlock).and_then(|()| write_private(&path(ctx), &json)).map_err(|e| e.to_string())
}

/// Try Touch ID, when the profile has the protector: `Some` session on success; `None` to go on to the PIN or the
/// master password. `why`: what asks for the unlock, when not the user.
pub(super) async fn unlock<H: Host>(host: &H, ctx: &Ctx, caller: &Caller, why: Option<&str>) -> Option<Session> {
    let stored = read(ctx)?;
    let (device, machine) = binding(host, ctx)?;
    let (mut blob, handle, ephemeral) = match stored {
        Ok(stored) => stored,
        Err(e) => {
            drop_biometric(ctx, caller, &e.to_string());
            return None;
        }
    };
    let account = session::account(host, ctx).await?;
    let why = why.map(|w| format!(": {w}")).unwrap_or_default();
    let reason = format!("Unlock dybw profile {}{why}", ctx.profile.name);
    let secret = match host.enclave_derive(handle, ephemeral, reason).await {
        Ok(secret) => secret,
        Err(enclave::Error::Invalidated) => {
            audit_as(ctx, caller, BIOMETRIC, "unlock-biometric", Verdict::Denied);
            drop_biometric(ctx, caller, "the Secure Enclave key no longer works (the enrolled fingers changed)");
            return None;
        }
        Err(e) => {
            // Kept: a cancel, no sensor, a lockout or an unknown error (its code logged) is no reason to delete it.
            let verdict = if e == enclave::Error::Cancelled { Verdict::Declined } else { Verdict::Failed };
            tracing::info!(profile = %ctx.profile.name, "Touch ID did not unlock: {e}");
            audit_as(ctx, caller, BIOMETRIC, "unlock-biometric", verdict);
            return None;
        }
    };
    let bound = Binding { device_id: &device, machine: &machine };
    let user = match protector::unwrap(&mut blob, &Kek::Hardware(secret), bound, &account.0, &BlockingArgon2).await {
        Ok(user) => user,
        Err(e) => {
            // Binding, Stale (a rotation), Wrong (bytes from another key), Format: the core's text, never a secret.
            audit_as(ctx, caller, BIOMETRIC, "unlock-biometric", Verdict::Denied);
            drop_biometric(ctx, caller, &e.to_string());
            return None;
        }
    };
    match session::unlock_with_key(ctx, user, account).await {
        Ok(session) => {
            audit_as(ctx, caller, BIOMETRIC, "unlock-biometric", Verdict::Confirmed);
            Some(session)
        }
        Err(e) => {
            tracing::warn!(profile = %ctx.profile.name, "the biometric protector's key was refused: {e}");
            audit_as(ctx, caller, BIOMETRIC, "unlock-biometric", Verdict::Denied);
            drop_biometric(ctx, caller, "the account refused its key");
            None
        }
    }
}
