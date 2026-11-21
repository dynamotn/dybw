//! The `pin` protector (ADR 0006, profiles §4): a copy of the user key wrapped by Argon2id over a PIN, kept in the
//! worker's memory only. It survives the idle, sleep and `dybw lock` locks (they drop the keys, not the blob) and is
//! dropped when the agent exits, on a new login or a purge, on a user-key rotation seen at a sync, after
//! [`MAX_ATTEMPTS`] wrong PINs, and when it no longer fits this device or account.
//!
//! Enrolment needs the master password, typed on this device (ADR 0006); `config.toml` cannot add a protector. The
//! enrolment, removal and listing here serve every protector this build offers ([`offered`]): the `login` one is
//! kept on disk ([`super::login`]), and so is the `biometric` one ([`super::biometric`]). An unlock tries the PIN first: a cancel goes on to the master password, a wrong
//! PIN is counted, and every other failure drops the blob, is logged and audited, and goes on to the master password.

use dybw_core::crypto::{KdfParams, SymmetricKey};
use dybw_core::profile::protector::{
    self, Binding, Kek, KekSource, MAX_ATTEMPTS, Protector, ProtectorBlob, ProtectorError,
};
use dybw_native::ports::kdf::BlockingArgon2;
use dybw_native::ports::random::OsRandom;
use dybw_proto::{AgentError, ProtectorInfo, Reply};
use zeroize::Zeroizing;

use super::{Recheck, Shared, biometric, error, login, open as open_profile, with_vault};
use crate::caller::Caller;
use crate::device::device_id_for;
use crate::host::Host;
use crate::policy::{AuditEvent, Verdict};
use crate::session::{self, Ctx, Session};

/// The protector kept in memory.
pub(crate) const PIN: &str = "pin";

/// Argon2id for a PIN or a login password: above ADR 0006's floors (64 MiB, t = 3, p = 1) in memory, the cost that
/// hurts a GPU most. An unlock with it takes about 0.35 s on an Apple M-series Mac.
pub(crate) const PIN_KDF: KdfParams = KdfParams::Argon2id { iterations: 3, memory_mib: 256, parallelism: 4 };

/// The shortest PIN: six characters. Five tries against a million six-digit PINs is a 1 in 200,000 chance of a
/// guess; a copy of the blob taken from the agent's memory costs about four CPU-days to search all six digits.
pub(crate) const MIN_PIN: usize = 6;

/// How often the new secret may be mistyped at enrolment before it gives up.
const TRIES: usize = 3;

/// The protector `name` names, when this build offers it: `pin` everywhere, `login` on Linux only (`pam_bwss`),
/// `biometric` on macOS only (the Secure Enclave).
pub(crate) fn offered(name: &str) -> Option<Protector> {
    match name {
        PIN => Some(Protector::Pin),
        #[cfg(any(target_os = "linux", test))]
        login::LOGIN => Some(Protector::Login),
        #[cfg(any(target_os = "macos", test))]
        biometric::BIOMETRIC => Some(Protector::Biometric),
        _ => None,
    }
}

fn audit(ctx: &Ctx, caller: &Caller, op: &'static str, verdict: Verdict) {
    audit_as(ctx, caller, PIN, op, verdict);
}

/// One local unlock line in the log and the audit, for the protector `kind`; never a secret.
pub(super) fn audit_as(ctx: &Ctx, caller: &Caller, kind: &'static str, op: &'static str, verdict: Verdict) {
    audit_via(ctx, caller, (kind, op), verdict, None);
}

/// [`audit_as`], with where the user answered (`channel`: the Touch ID sheet of a `biometric` unlock).
pub(super) fn audit_via(
    ctx: &Ctx,
    caller: &Caller,
    (kind, op): (&'static str, &'static str),
    verdict: Verdict,
    channel: Option<&'static str>,
) {
    tracing::info!(profile = %ctx.profile.name, op, kind, ?verdict, channel, "local unlock");
    ctx.audit.record(AuditEvent {
        time: std::time::SystemTime::now(),
        profile: ctx.profile.name.clone(),
        caller: caller.clone(),
        op,
        kind: Some(kind),
        item: None,
        verdict,
        ssh: None,
        channel,
    });
}

/// The device id and the machine fingerprint a blob is bound to; `None` when either cannot be read.
pub(super) fn binding<H: Host>(host: &H, ctx: &Ctx) -> Option<(String, String)> {
    // An unreadable device id stops the master password path too, which logs why.
    let device = device_id_for(&ctx.paths, ctx.user.uid).ok()?;
    let Some(machine) = host.machine() else {
        tracing::warn!(profile = %ctx.profile.name, "local unlock: the machine fingerprint cannot be read");
        return None;
    };
    Some((device, machine))
}

/// The profile's protectors: names and attempts left (none with `names_only`, and none for `login`, which has no
/// limit: the system checked its password before `pam_bwss` handed it over, nor for `biometric`, whose tries Touch ID
/// counts), never a secret.
pub(super) fn infos(shared: &Shared, ctx: &Ctx, names_only: bool) -> Vec<ProtectorInfo> {
    let left = |b: &ProtectorBlob| (!names_only).then(|| MAX_ATTEMPTS.saturating_sub(b.attempts()));
    let pin = shared.state.borrow().pin.as_ref().map(|b| ProtectorInfo { name: PIN.into(), attempts_left: left(b) });
    let login = login::enrolled(ctx).then(|| ProtectorInfo { name: login::LOGIN.into(), attempts_left: None });
    let touch =
        biometric::enrolled(ctx).then(|| ProtectorInfo { name: biometric::BIOMETRIC.into(), attempts_left: None });
    pin.into_iter().chain(login).chain(touch).collect()
}

/// `dybw unlock list`.
pub(super) fn list(shared: &Shared, ctx: &Ctx, names_only: bool) -> Reply {
    Reply::Protectors { profile: ctx.profile.name.clone(), protectors: infos(shared, ctx, names_only) }
}

/// Every protector name, offered by this build or not: a file another build left can still be removed.
fn named(name: &str) -> Option<Protector> {
    match name {
        PIN => Some(Protector::Pin),
        login::LOGIN => Some(Protector::Login),
        biometric::BIOMETRIC => Some(Protector::Biometric),
        _ => None,
    }
}

/// `dybw unlock remove <protector>`: refused to any caller but a named invoker, audited.
pub(super) fn remove(shared: &Shared, ctx: &Ctx, caller: &Caller, name: &str) -> Reply {
    let kind = named(name);
    let shown = kind.map_or(PIN, Protector::name);
    if !matches!(caller, Caller::Invoker { .. }) {
        audit_as(ctx, caller, shown, "unlock-remove", Verdict::Denied);
        return error(AgentError::Denied);
    }
    let removed = match kind {
        Some(Protector::Pin) => shared.state.borrow_mut().pin.take().is_some(),
        Some(Protector::Biometric) => biometric::delete(ctx),
        Some(_) => login::delete(ctx),
        None => false,
    };
    if !removed {
        return error(AgentError::NoSuchProtector(name.into()));
    }
    audit_as(ctx, caller, shown, "unlock-remove", Verdict::Confirmed);
    Reply::Done
}

/// Drop the blob, saying why in the log and the audit (`unlock-pin-dropped`), under the caller whose request did it.
pub(super) fn drop_pin(shared: &Shared, ctx: &Ctx, caller: &Caller, why: &str) {
    if shared.state.borrow_mut().pin.take().is_some() {
        tracing::warn!(profile = %ctx.profile.name, "the PIN was dropped: {why}");
        audit(ctx, caller, "unlock-pin-dropped", Verdict::Failed);
    }
}

/// Drop every protector of the profile (a new login, a purge, a rotation), each logged and audited.
pub(super) fn drop_all(shared: &Shared, ctx: &Ctx, caller: &Caller, why: &str) {
    drop_pin(shared, ctx, caller, why);
    login::drop_login(ctx, caller, why);
    biometric::drop_biometric(ctx, caller, why);
}

/// The caller of what the agent does on its own (a sync's rotation check, a login password handed over): its own
/// executable.
pub(crate) fn the_agent() -> Caller {
    let exe = std::env::current_exe().unwrap_or_default();
    Caller::Invoker { exe, script: None, hash: String::new(), relative: false, at: Default::default() }
}

/// Ask for the new secret twice: the same both times and, for a PIN, at least [`MIN_PIN`] characters, else asked
/// again.
async fn new_secret<H: Host>(host: &H, ctx: &Ctx, kind: Protector) -> Result<Zeroizing<String>, AgentError> {
    let name = &ctx.profile.name;
    let (label, first, min, short, differ) = if kind == Protector::Pin {
        let first = format!(
            "dybw profile {name}: choose a PIN of at least {MIN_PIN} characters to unlock this profile on this device. \
             It stays in the agent's memory only; {MAX_ATTEMPTS} wrong PINs drop it."
        );
        ("PIN", first, MIN_PIN, "The PIN is too short.", "The two PINs differ.")
    } else {
        // An empty answer is a cancel, so a login password is never too short.
        ("Login password", login::enrol_text(name), 1, "The login password is too short.", "The two passwords differ.")
    };
    let again = format!("dybw profile {name}: type the same {} again.", label.to_lowercase());
    let (prompt, prompt_again) = (format!("{label}:"), format!("{label} again:"));
    let mut wrong = None;
    for _ in 0..TRIES {
        let secret = session::ask(host, &prompt, &first, wrong).await?;
        if secret.chars().count() < min {
            wrong = Some(short);
            continue;
        }
        if *session::ask(host, &prompt_again, &again, None).await? == *secret {
            return Ok(secret);
        }
        wrong = Some(differ);
    }
    Err(AgentError::Denied)
}

/// `dybw unlock add <protector>`: unlock with the master password when locked, else ask for it (enrolment needs it,
/// ADR 0006), then the new secret twice, or for `biometric` a new Secure Enclave key (`options`: `--any`, `--watch`;
/// ignored for the others); the protector replaces any earlier one. Refused to any caller but a named invoker.
/// Audited.
pub(super) async fn add<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    still: &Recheck,
    name: &str,
    options: (bool, bool),
) -> Reply {
    let kind = offered(name);
    if !matches!(caller, Caller::Invoker { .. }) {
        audit_as(ctx, caller, kind.map_or(PIN, Protector::name), "unlock-add", Verdict::Denied);
        return error(AgentError::Denied);
    }
    // A Mac without a Secure Enclave has no `biometric`: said before the master password is asked.
    let Some(kind) = kind.filter(|k| *k != Protector::Biometric || host.enclave()) else {
        return error(AgentError::NoSuchProtector(name.into()));
    };
    // Only a master password typed for this very unlock counts: a profile another unlock (a PIN) opened meanwhile
    // asks for it again below.
    let (unlocked, typed) = open_profile(shared, host, ctx, caller, None, false).await;
    if unlocked != Reply::Done {
        return unlocked;
    }
    let _screen = shared.asking.lock().await;
    let result = enrol(shared, host, ctx, still, typed, kind, options).await;
    audit_as(ctx, caller, kind.name(), "unlock-add", result.as_ref().map_or_else(|(_, v)| *v, |()| Verdict::Confirmed));
    result.map_or_else(|(e, _)| error(e), |()| Reply::Done)
}

/// The enrolment after the unlock; a failure says how to audit it: `Denied` for a wrong master password or a caller
/// that changed, `Declined` for a cancelled question, `Failed` for the rest.
async fn enrol<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    still: &Recheck,
    typed: bool,
    kind: Protector,
    (any, watch): (bool, bool),
) -> Result<(), (AgentError, Verdict)> {
    let declined = |e| (e, Verdict::Declined);
    let failed = |e| (e, Verdict::Failed);
    if !typed {
        match master_password(shared, host, ctx, kind).await {
            Ok(true) => {}
            Ok(false) => return Err((AgentError::Denied, Verdict::Denied)),
            Err(e) => return Err(declined(e)),
        }
    }
    // Touch ID is not asked at enrolment: the wrap needs only the enclave key's public half.
    let secret = match kind {
        Protector::Biometric => None,
        _ => Some(new_secret(host, ctx, kind).await.map_err(declined)?),
    };
    if !still.holds() {
        return Err((AgentError::Denied, Verdict::Denied));
    }
    let (device, machine) = binding(host, ctx).ok_or(failed(AgentError::Internal))?;
    let user =
        with_vault(shared, |v| SymmetricKey::from_bytes(&v.keys.user().to_bytes()).map_err(|_| AgentError::Internal))
            .map_err(failed)?;
    let bound = (device.as_str(), machine.as_str());
    let Some(secret) = secret else {
        // One write of the protector's file at a time, as for `login`.
        let _op = shared.op.lock().await;
        return biometric::enrol(host, ctx, &user, bound, any, watch).await.map_err(|e| {
            tracing::warn!(profile = %ctx.profile.name, kind = "biometric", "not enrolled: {e}");
            failed(AgentError::Internal)
        });
    };
    let source = KekSource::Secret { secret: Zeroizing::new(secret.as_bytes().to_vec()), params: PIN_KDF };
    drop(secret);
    let bound = Binding { device_id: &device, machine: &machine };
    let blob = protector::wrap(&user, kind, source, bound, &BlockingArgon2, &OsRandom).await.map_err(|e| {
        tracing::warn!(profile = %ctx.profile.name, kind = kind.name(), "not enrolled: {}", e.code());
        failed(AgentError::Internal)
    })?;
    if kind == Protector::Pin {
        shared.state.borrow_mut().pin = Some(blob);
        return Ok(());
    }
    // One write of the protector's files at a time: a password handed over meanwhile waits (ruling L3).
    let _op = shared.op.lock().await;
    login::save(ctx, login::LOGIN, &blob).map_err(|e| {
        tracing::warn!(profile = %ctx.profile.name, "the login protector was not saved: {}", e.kind());
        failed(AgentError::Internal)
    })?;
    // A fresh enrolment replaces a re-wrap still waiting for a login.
    login::forget_pending(ctx);
    Ok(())
}

/// The master password, checked against the unlocked user key and never sent anywhere (as a reprompt is): whether it
/// was right.
async fn master_password<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, kind: Protector) -> Result<bool, AgentError> {
    let account = |s: &Session| {
        let part = |k: &str| s.vault.sync.get(k).cloned().unwrap_or_default();
        (s.origin.clone(), serde_json::json!({ "profile": part("profile"), "userDecryption": part("userDecryption") }))
    };
    let target = shared.state.borrow().slot.as_ref().map(|s| (account(s), s.vault.user_key_id()));
    let Some(((origin, account), unlocked)) = target else { return Err(AgentError::Locked) };
    let what = match kind {
        Protector::Pin => "a PIN",
        Protector::Biometric => "Touch ID",
        _ => "unlock at login",
    };
    let description =
        format!("dybw profile {}: type the master password to set {what} for this device", ctx.profile.name);
    let password = session::ask(host, "Master password:", &description, None).await?;
    Ok(session::key_id_of(ctx, &origin, account, password).await?.is_some_and(|id| id == unlocked))
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
            st.pin = st.pin.take().map(|_| blob.clone());
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
                        drop_pin(shared, ctx, caller, "the account refused its key");
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
                // Binding, Stale (a rotation), Invalidated, Format: the core's text names which, never a secret.
                let why = if e == ProtectorError::Wrong { "five wrong PINs".to_owned() } else { e.to_string() };
                drop_pin(shared, ctx, caller, &why);
                return None;
            }
        }
    }
}

/// After a sync: drop every protector when the user key no longer opens the account (a rotation).
pub(super) async fn after_sync(shared: &Shared, ctx: &Ctx, sync: &serde_json::Value) {
    if shared.state.borrow().pin.is_none() && !login::enrolled(ctx) && !biometric::enrolled(ctx) {
        return;
    }
    let user =
        with_vault(shared, |v| SymmetricKey::from_bytes(&v.keys.user().to_bytes()).map_err(|_| AgentError::Internal));
    let Ok(user) = user else { return };
    if !session::key_still_opens(ctx, &user, sync).await {
        drop_all(shared, ctx, &the_agent(), "the user key no longer opens the account (rotated)");
    }
}
