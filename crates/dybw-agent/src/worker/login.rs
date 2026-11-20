//! The `login` protector (ADR 0006): a copy of the user key wrapped by Argon2id over the Linux login password, on
//! disk at `<state>/unlock/login` (0600, its directory 0700, written whole), bound to the device. `pam_bwss` hands the
//! password to the user's kernel keyring at a login or a screen unlock; the agent's handover ([`crate::handover`])
//! passes it to every worker with this protector, once, and drops it right after. Enrolment is in [`super::pin`]
//! (Linux only); this file keeps the blob and acts on a password handed over.
//!
//! A password change gives the old and the new password: the key is wrapped again for the new one into
//! `login.pending`, and the old blob stays until a login shows which password is current (ruling L5): the pending
//! blob opens, and it replaces the old one; the old one opens, and the pending one goes. A login password that opens
//! neither invalidates the protector (ADR 0006: a password reset by root, or one changed where `pam_bwss` did not see
//! it), as does any other failure (another device, a rotated key, an unreadable blob): the blobs are deleted, logged
//! and audited, and the next unlock asks for the PIN or the master password; enrolling again needs the master
//! password. An old password that does not open the protector at a change re-wraps nothing and deletes nothing: the
//! next login decides.

use std::path::PathBuf;

use dybw_core::crypto::SymmetricKey;
use dybw_core::profile::protector::{self, Binding, Kek, KekSource, Protector, ProtectorBlob, ProtectorError};
use dybw_native::fsutil::{ensure_private_dir, write_private};
use dybw_native::ports::kdf::BlockingArgon2;
use dybw_native::ports::random::OsRandom;
use dybw_proto::{AgentError, Reply};
use zeroize::Zeroizing;

use super::pin::{PIN_KDF, audit_as, binding, the_agent};
use super::{Shared, error, opened};
use crate::caller::Caller;
use crate::host::Host;
use crate::policy::Verdict;
use crate::session::{self, Ctx};

/// The protector's name, and its file under `<state>/unlock`.
pub(crate) const LOGIN: &str = "login";
/// A re-wrap for a new password, waiting for a login to confirm it.
const PENDING: &str = "login.pending";

/// What the pinentry says when the login password is asked for at enrolment.
pub(super) fn enrol_text(profile: &str) -> String {
    format!(
        "dybw profile {profile}: type the password you log in to this computer with. It is not checked against the \
         system: type it exactly. Logging in then unlocks this profile. Without a TPM2, someone who takes this disk \
         can guess that password offline from the copy kept here."
    )
}

fn path(ctx: &Ctx, file: &str) -> PathBuf {
    ctx.paths.unlock.join(file)
}

/// Whether the profile has a `login` protector on this device.
pub(super) fn enrolled(ctx: &Ctx) -> bool {
    path(ctx, LOGIN).exists()
}

/// Write `blob` as `file`, whole, 0600 in a 0700 directory.
pub(super) fn save(ctx: &Ctx, file: &str, blob: &ProtectorBlob) -> std::io::Result<()> {
    ensure_private_dir(&ctx.paths.unlock)?;
    write_private(&path(ctx, file), &blob.to_json())
}

/// Delete the pending re-wrap, if any.
pub(super) fn forget_pending(ctx: &Ctx) {
    let _ = std::fs::remove_file(path(ctx, PENDING));
}

/// Delete the protector and any pending re-wrap: whether there was one.
pub(super) fn delete(ctx: &Ctx) -> bool {
    forget_pending(ctx);
    std::fs::remove_file(path(ctx, LOGIN)).is_ok()
}

/// [`delete`], saying why in the log and the audit (`unlock-login-dropped`).
pub(super) fn drop_login(ctx: &Ctx, caller: &Caller, why: &str) {
    if delete(ctx) {
        tracing::warn!(profile = %ctx.profile.name, "the login protector was dropped: {why}");
        audit_as(ctx, caller, LOGIN, "unlock-login-dropped", Verdict::Failed);
    }
}

/// The blob `file`: `None` when there is no such file. A blob of another protector is unreadable here.
fn read(ctx: &Ctx, file: &str) -> Option<Result<ProtectorBlob, ProtectorError>> {
    let raw = std::fs::read(path(ctx, file)).ok()?;
    let blob = ProtectorBlob::from_json(&raw);
    Some(blob.and_then(|b| if b.protector() == Protector::Login { Ok(b) } else { Err(ProtectorError::Format) }))
}

/// Open `blob` with `secret`. The count of failures is never written back: a login password has no attempt limit.
async fn open(
    blob: Result<ProtectorBlob, ProtectorError>,
    (device, machine): &(String, String),
    sync: &serde_json::Value,
    secret: &[u8],
) -> Result<SymmetricKey, ProtectorError> {
    let kek = Kek::Secret(Zeroizing::new(secret.to_vec()));
    let bound = Binding { device_id: device, machine };
    protector::unwrap(&mut blob?, &kek, bound, sync, &BlockingArgon2).await
}

/// A login password `pam_bwss` handed over: with `old` (a password change), wrap the key again for the new one; else
/// unlock with it. Nothing is done for a profile without the protector.
pub(super) async fn on_token<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, token: &[u8], old: Option<&[u8]>) -> Reply {
    let agent = the_agent();
    match old {
        Some(old) => rewrap(shared, host, ctx, &agent, old, token).await,
        None => unlock(shared, host, ctx, &agent, token).await,
    }
}

/// Unlock with the login password: the pending re-wrap first, then the protector. An unlocked profile is left as is.
async fn unlock<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, agent: &Caller, token: &[u8]) -> Reply {
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    let _op = shared.op.lock().await;
    // Another unlock may have finished while this one waited for its turn.
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    let Some(main) = read(ctx, LOGIN) else { return Reply::Done };
    let Some(bound) = binding(host, ctx) else { return error(AgentError::Internal) };
    let Some(account) = session::account(host, ctx).await else {
        tracing::warn!(profile = %ctx.profile.name, "the login password came, but the account cannot be read");
        return error(AgentError::Locked);
    };
    let pending = match read(ctx, PENDING) {
        Some(blob) => open(blob, &bound, &account.0, token).await,
        None => Err(ProtectorError::Wrong),
    };
    // The new password is the current one when the pending wrap opens: it replaces the old once the account took it.
    let promote = pending.is_ok();
    let user = match pending {
        Ok(user) => Ok(user),
        Err(e) => {
            if e != ProtectorError::Wrong {
                tracing::warn!(profile = %ctx.profile.name, "the pending login protector was deleted: {e}");
                forget_pending(ctx);
            }
            open(main, &bound, &account.0, token).await.inspect(|_| {
                // The old password still opens it: the change did not happen.
                forget_pending(ctx);
            })
        }
    };
    let user = match user {
        Ok(user) => user,
        Err(e) => {
            // Wrong: the password changed without a re-wrap (a reset by root), so the protector is no longer the
            // login password's (ruling C1).
            audit_as(ctx, agent, LOGIN, "unlock-login", Verdict::Denied);
            let why = if e == ProtectorError::Wrong {
                "the login password opens it no more".to_owned()
            } else {
                e.to_string()
            };
            drop_login(ctx, agent, &why);
            return error(AgentError::Denied);
        }
    };
    match session::unlock_with_key(ctx, user, account).await {
        Ok(session) => {
            if promote {
                let promoted = std::fs::rename(path(ctx, PENDING), path(ctx, LOGIN)).is_ok();
                tracing::info!(profile = %ctx.profile.name, promoted, "the login protector of the new password is in use");
            }
            opened(shared, session);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            shared.state.borrow_mut().handover = Some(now.as_secs());
            audit_as(ctx, agent, LOGIN, "unlock-login", Verdict::Confirmed);
            Reply::Done
        }
        Err(e) => {
            tracing::warn!(profile = %ctx.profile.name, "the login protector's key was refused: {e}");
            audit_as(ctx, agent, LOGIN, "unlock-login", Verdict::Denied);
            drop_login(ctx, agent, "the account refused its key");
            error(e)
        }
    }
}

/// A password change: the key the old password opens (the protector, else a pending re-wrap from an earlier change)
/// is wrapped for the new one into the pending file. The protector itself stays until a login confirms (ruling L5).
async fn rewrap<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, agent: &Caller, old: &[u8], new: &[u8]) -> Reply {
    let _op = shared.op.lock().await;
    let Some(main) = read(ctx, LOGIN) else { return Reply::Done };
    let Some(bound) = binding(host, ctx) else { return error(AgentError::Internal) };
    let Some(account) = session::account(host, ctx).await else {
        tracing::warn!(profile = %ctx.profile.name, "the password changed, but the account cannot be read");
        return error(AgentError::Locked);
    };
    let mut found = open(main, &bound, &account.0, old).await;
    if matches!(found, Err(ProtectorError::Wrong))
        && let Some(pending) = read(ctx, PENDING)
        && let Ok(user) = open(pending, &bound, &account.0, old).await
    {
        found = Ok(user);
    }
    let user = match found {
        Ok(user) => user,
        Err(e) => {
            audit_as(ctx, agent, LOGIN, "unlock-login-rewrap", Verdict::Denied);
            if e == ProtectorError::Wrong {
                tracing::warn!(profile = %ctx.profile.name, "the old login password does not open the login protector");
            } else {
                drop_login(ctx, agent, &e.to_string());
            }
            return error(AgentError::Denied);
        }
    };
    let source = KekSource::Secret { secret: Zeroizing::new(new.to_vec()), params: PIN_KDF };
    let binding = Binding { device_id: &bound.0, machine: &bound.1 };
    let wrapped = protector::wrap(&user, Protector::Login, source, binding, &BlockingArgon2, &OsRandom).await;
    let saved = wrapped.map_err(std::io::Error::other).and_then(|blob| save(ctx, PENDING, &blob));
    let verdict = match &saved {
        Ok(()) => Verdict::Confirmed,
        Err(e) => {
            tracing::warn!(profile = %ctx.profile.name, "the login protector was not wrapped for the new password: {e}");
            Verdict::Failed
        }
    };
    audit_as(ctx, agent, LOGIN, "unlock-login-rewrap", verdict);
    saved.map_or_else(|_| error(AgentError::Internal), |()| Reply::Done)
}
