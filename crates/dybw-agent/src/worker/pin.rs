//! The `pin` protector (ADR 0006, profiles §4): a copy of the user key wrapped by Argon2id over a PIN, kept in the
//! worker's memory only. It survives the idle, sleep and `dybw lock` locks (they drop the keys, not the blob) and is
//! dropped when the agent exits, on a new login or a purge, on a user-key rotation seen at a sync, after
//! [`MAX_ATTEMPTS`] wrong PINs, and when it no longer fits this device or account.
//!
//! Enrolment needs the master password, typed on this device (ADR 0006); `config.toml` cannot add a protector. An
//! unlock tries the PIN first: a cancel goes on to the master password, a wrong PIN is counted, and every other
//! failure drops the blob, is logged and audited, and goes on to the master password.

use dybw_core::crypto::{KdfParams, SymmetricKey};
use dybw_core::profile::protector::{
    self, Binding, Kek, KekSource, MAX_ATTEMPTS, Protector, ProtectorBlob, ProtectorError,
};
use dybw_native::ports::kdf::BlockingArgon2;
use dybw_native::ports::random::OsRandom;
use dybw_proto::{AgentError, ProtectorInfo, Reply};
use zeroize::Zeroizing;

use super::{Recheck, Shared, error, unlock as unlock_profile, with_vault};
use crate::caller::Caller;
use crate::device::device_id_for;
use crate::host::Host;
use crate::policy::{AuditEvent, Verdict};
use crate::session::{self, Ctx, Session};

/// The only protector this build offers.
pub(crate) const PIN: &str = "pin";

/// Argon2id for a PIN: above ADR 0006's floors (64 MiB, t = 3, p = 1) in memory, the cost that hurts a GPU most.
/// An unlock with it takes about 0.35 s on an Apple M-series Mac.
pub(crate) const PIN_KDF: KdfParams = KdfParams::Argon2id { iterations: 3, memory_mib: 256, parallelism: 4 };

/// The shortest PIN: six characters. Five tries against a million six-digit PINs is a 1 in 200,000 chance of a
/// guess; a copy of the blob taken from the agent's memory costs about four CPU-days to search all six digits.
pub(crate) const MIN_PIN: usize = 6;

/// How often the PIN pair may be mistyped at enrolment before it gives up.
const TRIES: usize = 3;

fn audit(ctx: &Ctx, caller: &Caller, op: &'static str, verdict: Verdict) {
    tracing::info!(profile = %ctx.profile.name, op, ?verdict, "local unlock");
    ctx.audit.record(AuditEvent {
        time: std::time::SystemTime::now(),
        profile: ctx.profile.name.clone(),
        caller: caller.clone(),
        op,
        kind: Some(PIN),
        item: None,
        verdict,
        ssh: None,
    });
}

/// The device id and the machine fingerprint a blob is bound to; `None` when either cannot be read.
fn binding<H: Host>(host: &H, ctx: &Ctx) -> Option<(String, String)> {
    let device = device_id_for(&ctx.paths, ctx.user.uid)
        .map_err(|e| tracing::warn!(profile = %ctx.profile.name, "local unlock: device id: {e:#}"))
        .ok()?;
    let Some(machine) = host.machine() else {
        tracing::warn!(profile = %ctx.profile.name, "local unlock: the machine fingerprint cannot be read");
        return None;
    };
    Some((device, machine))
}

/// `dybw unlock list`: names and attempts left, never a secret.
pub(super) fn list(shared: &Shared, ctx: &Ctx) -> Reply {
    let protectors = shared
        .state
        .borrow()
        .pin
        .as_ref()
        .map(|b| ProtectorInfo { name: PIN.into(), attempts_left: MAX_ATTEMPTS.saturating_sub(b.attempts()) });
    Reply::Protectors { profile: ctx.profile.name.clone(), protectors: protectors.into_iter().collect() }
}

/// `dybw unlock remove pin`: refused to any caller but a named invoker, audited.
pub(super) fn remove(shared: &Shared, ctx: &Ctx, caller: &Caller, name: &str) -> Reply {
    if !matches!(caller, Caller::Invoker { .. }) {
        audit(ctx, caller, "unlock-remove", Verdict::Denied);
        return error(AgentError::Denied);
    }
    if name != PIN || shared.state.borrow_mut().pin.take().is_none() {
        return error(AgentError::NoSuchProtector(name.into()));
    }
    audit(ctx, caller, "unlock-remove", Verdict::Confirmed);
    Reply::Done
}

/// Drop the blob, saying why in the log, and in the audit (`unlock-pin-dropped`) when a caller's request did it.
pub(super) fn drop_pin(shared: &Shared, ctx: &Ctx, caller: Option<&Caller>, why: &str) {
    if shared.state.borrow_mut().pin.take().is_some() {
        tracing::warn!(profile = %ctx.profile.name, "the PIN was dropped: {why}");
        if let Some(caller) = caller {
            audit(ctx, caller, "unlock-pin-dropped", Verdict::Failed);
        }
    }
}

/// Ask for the new PIN twice: the same both times and at least [`MIN_PIN`] characters, else asked again.
async fn new_pin<H: Host>(host: &H, ctx: &Ctx) -> Result<Zeroizing<String>, AgentError> {
    let name = &ctx.profile.name;
    let first = format!(
        "dybw profile {name}: choose a PIN of at least {MIN_PIN} characters to unlock this profile on this device. It \
         stays in the agent's memory only; {MAX_ATTEMPTS} wrong PINs drop it."
    );
    let again = format!("dybw profile {name}: type the same PIN again.");
    let mut wrong = None;
    for _ in 0..TRIES {
        let pin = session::ask(host, "PIN:", &first, wrong).await?;
        if pin.chars().count() < MIN_PIN {
            wrong = Some("The PIN is too short.");
            continue;
        }
        if *session::ask(host, "PIN again:", &again, None).await? == *pin {
            return Ok(pin);
        }
        wrong = Some("The two PINs differ.");
    }
    Err(AgentError::Denied)
}

/// `dybw unlock add pin`: unlock with the master password when locked, else ask for it (enrolment needs it, ADR 0006),
/// then the PIN twice; the blob replaces any earlier one. Refused to any caller but a named invoker. Audited.
pub(super) async fn add<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    still: &Recheck,
    name: &str,
) -> Reply {
    if !matches!(caller, Caller::Invoker { .. }) {
        audit(ctx, caller, "unlock-add", Verdict::Denied);
        return error(AgentError::Denied);
    }
    if name != PIN {
        return error(AgentError::NoSuchProtector(name.into()));
    }
    let typed = shared.state.borrow().slot.is_none();
    if typed {
        let unlocked = unlock_profile(shared, host, ctx, caller, None, false).await;
        if unlocked != Reply::Done {
            return unlocked;
        }
    }
    let _screen = shared.asking.lock().await;
    let result = enrol(shared, host, ctx, still, typed).await;
    audit(ctx, caller, "unlock-add", if result.is_ok() { Verdict::Confirmed } else { Verdict::Declined });
    result.map_or_else(error, |()| Reply::Done)
}

async fn enrol<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, still: &Recheck, typed: bool) -> Result<(), AgentError> {
    if !typed {
        master_password(shared, host, ctx).await?;
    }
    let pin = new_pin(host, ctx).await?;
    if !still.holds() {
        return Err(AgentError::Denied);
    }
    let (device, machine) = binding(host, ctx).ok_or(AgentError::Internal)?;
    let user =
        with_vault(shared, |v| SymmetricKey::from_bytes(&v.keys.user().to_bytes()).map_err(|_| AgentError::Internal))?;
    let source = KekSource::Secret { secret: Zeroizing::new(pin.as_bytes().to_vec()), params: PIN_KDF };
    drop(pin);
    let bound = Binding { device_id: &device, machine: &machine };
    let blob =
        protector::wrap(&user, Protector::Pin, source, bound, &BlockingArgon2, &OsRandom).await.map_err(|e| {
            tracing::warn!(profile = %ctx.profile.name, "the PIN was not enrolled: {}", e.code());
            AgentError::Internal
        })?;
    // Locked while the PIN was typed: the key above was the unlocked one, but the user is gone.
    if shared.state.borrow().slot.is_none() {
        return Err(AgentError::Locked);
    }
    shared.state.borrow_mut().pin = Some(blob);
    Ok(())
}

/// The master password, checked against the unlocked user key and never sent anywhere (as a reprompt is).
async fn master_password<H: Host>(shared: &Shared, host: &H, ctx: &Ctx) -> Result<(), AgentError> {
    let account = |s: &Session| {
        let part = |k: &str| s.vault.sync.get(k).cloned().unwrap_or_default();
        (s.origin.clone(), serde_json::json!({ "profile": part("profile"), "userDecryption": part("userDecryption") }))
    };
    let target = shared.state.borrow().slot.as_ref().map(|s| (account(s), s.vault.user_key_id()));
    let Some(((origin, account), unlocked)) = target else { return Err(AgentError::Locked) };
    let description =
        format!("dybw profile {}: type the master password to set a PIN for this device", ctx.profile.name);
    let password = session::ask(host, "Master password:", &description, None).await?;
    match session::key_id_of(ctx, &origin, account, password).await? {
        Some(id) if id == unlocked => Ok(()),
        _ => Err(AgentError::Denied),
    }
}

/// Try the PIN, when there is one: `Some` session on success; `None` to go on to the master password (no PIN, a
/// cancel, the attempts used up, or a blob dropped for another reason). The account is read once, online if the
/// server answers, else from the offline copy, before the first question.
pub(super) async fn unlock<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    why: Option<&str>,
) -> Option<Session> {
    shared.state.borrow().pin.as_ref()?;
    let (device, machine) = binding(host, ctx)?;
    let account = session::account(host, ctx).await?;
    let why = why.map(|w| format!(": {w}")).unwrap_or_default();
    let mut wrong = None;
    loop {
        let left = MAX_ATTEMPTS.saturating_sub(shared.state.borrow().pin.as_ref()?.attempts());
        let description = format!(
            "Unlock dybw profile {}{why} with its PIN ({left} tries left). Cancel to type the master password instead.",
            ctx.profile.name
        );
        let pin = session::ask(host, "PIN:", &description, wrong).await.ok()?;
        let kek = Kek::Secret(Zeroizing::new(pin.as_bytes().to_vec()));
        drop(pin);
        // Taken out and put back with its count, unless a remove dropped it meanwhile.
        let mut blob: ProtectorBlob = shared.state.borrow().pin.clone()?;
        let bound = Binding { device_id: &device, machine: &machine };
        let result = protector::unwrap(&mut blob, &kek, bound, &account.0, &BlockingArgon2).await;
        {
            let mut st = shared.state.borrow_mut();
            if st.pin.is_some() {
                st.pin = Some(blob.clone());
            }
        }
        match result {
            Ok(user) => {
                return match session::unlock_with_key(ctx, user, account).await {
                    Ok(session) => {
                        audit(ctx, caller, "unlock-pin", Verdict::Confirmed);
                        Some(session)
                    }
                    Err(e) => {
                        tracing::warn!(profile = %ctx.profile.name, "the PIN's key was refused: {e}");
                        drop_pin(shared, ctx, Some(caller), "the account refused its key");
                        None
                    }
                };
            }
            Err(ProtectorError::Wrong) if !blob.invalidated() => {
                audit(ctx, caller, "unlock-pin", Verdict::Denied);
                wrong = Some("Wrong PIN.");
            }
            Err(e) => {
                audit(ctx, caller, "unlock-pin", Verdict::Denied);
                let why = match e {
                    ProtectorError::Wrong | ProtectorError::Invalidated => "too many wrong PINs",
                    ProtectorError::Binding => "it belongs to another device or machine",
                    ProtectorError::Stale => "the user key no longer opens the account (rotated)",
                    _ => "it is unreadable",
                };
                drop_pin(shared, ctx, Some(caller), why);
                return None;
            }
        }
    }
}

/// After a sync: drop the PIN when the user key no longer opens the account (a rotation).
pub(super) async fn after_sync(shared: &Shared, ctx: &Ctx, sync: &serde_json::Value) {
    if shared.state.borrow().pin.is_none() {
        return;
    }
    let user =
        with_vault(shared, |v| SymmetricKey::from_bytes(&v.keys.user().to_bytes()).map_err(|_| AgentError::Internal));
    let Ok(user) = user else { return };
    if !session::key_still_opens(ctx, &user, sync).await {
        drop_pin(shared, ctx, None, "the user key no longer opens the account (rotated)");
    }
}
