//! The SSH agent's decisions on the profile's worker (P4.5, profiles §8, ADR 0012): the confirmation of a signature
//! and the unlock a signature asks for. On the worker, so a lock cancels a question in flight and drops every
//! "always" given for the profile's keys.

use dybw_proto::{AgentError, Reply};

use super::{MAX_HELD, Shared, error, quoted, unlock as unlock_profile};
use crate::caller::Caller;
use crate::host::Host;
use crate::policy::{self, Access, AuditEvent, Decision, Store, Verdict};
use crate::session::{self, Ctx};
use crate::ssh::Key;
use crate::ssh_agent::{Data, SignContext, client, host_key, sign_event};

/// The "no" answers after which a client is asked nothing more until the profile locks or unlocks.
pub(super) const MAX_NOES: u8 = 3;

/// Count a "no" for `caller`.
fn note_no(shared: &Shared, caller: &Caller) {
    let noes = &mut shared.state.borrow_mut().ssh_noes;
    match noes.iter_mut().find(|(c, _)| c == caller) {
        Some((_, n)) => *n = n.saturating_add(1),
        None => {
            if noes.len() >= MAX_HELD {
                noes.remove(0);
            }
            noes.push((caller.clone(), 1));
        }
    }
}

/// Ask whether `caller` may sign with `key`, unless this very process (pid, start time and image) holds an "always"
/// for this key and this kind of data (a login or not). "Always" follows the main socket's rule (a grant that can
/// last, never for a detached, AI-class or unknown caller, ADR 0012) and is never offered for, nor used by, a
/// forwarded request. One question on the screen at a time; a held answer is looked for again once this request has
/// the screen. A client refused [`MAX_NOES`] times is asked nothing more. Every decision is audited. `Done` allows
/// the signature.
pub(super) async fn confirm<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    key: &Key,
    sign: &SignContext,
) -> Reply {
    // A profile locked since the key was found asks nothing, and no "always" given to it may outlive the lock. The
    // SSH agent audits this refusal.
    let locked = || shared.state.borrow().slot.is_none();
    if locked() {
        return error(AgentError::Locked);
    }
    // A deny entry of the caller policy for this program refuses before any question; an allow entry never skips it.
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    let denied = matches!(caller, Caller::Invoker { .. })
        && policy::decide(caller, &store.load(), &[], Access::Value) == Decision::Deny;
    if denied {
        ctx.audit.record(sign_event(caller, key, sign, Verdict::Denied));
        return error(AgentError::Denied);
    }
    let forwarded = sign.bound.as_ref().is_some_and(|b| b.forwarded);
    let always = caller.rememberable() && !forwarded;
    let grant = (caller.clone(), key.blob.clone(), matches!(sign.data, Data::Login { .. }));
    let held = || always && shared.state.borrow().ssh_held.contains(&grant);
    let refused_enough = || shared.state.borrow().ssh_noes.iter().any(|(c, n)| c == caller && *n >= MAX_NOES);
    let mut channel = None;
    let verdict = if held() {
        Verdict::Granted
    } else {
        let _screen = shared.asking.lock().await;
        if held() {
            Verdict::Granted
        } else if refused_enough() {
            tracing::info!(profile = %ctx.profile.name, "not asking again for an SSH client refused {MAX_NOES} times");
            Verdict::Denied
        } else {
            let touch = touch_reason(&ctx.profile.name, caller, key, sign, forwarded);
            let (answer, via) = session::confirm(host, &text(ctx, caller, key, sign, always), touch, always).await;
            channel = Some(via);
            match answer {
                // Wiped while the question was open without this task being aborted (a crashed command).
                Ok(_) if locked() => return error(AgentError::Locked),
                Ok(true) if always => {
                    let held = &mut shared.state.borrow_mut().ssh_held;
                    if held.len() >= MAX_HELD {
                        held.remove(0);
                    }
                    held.push(grant);
                    Verdict::Remembered
                }
                Ok(_) => Verdict::Confirmed,
                Err(AgentError::Prompt) => Verdict::Failed,
                Err(_) => {
                    note_no(shared, caller);
                    Verdict::Declined
                }
            }
        }
    };
    ctx.audit.record(AuditEvent { channel, ..sign_event(caller, key, sign, verdict) });
    match verdict {
        Verdict::Declined | Verdict::Denied => error(AgentError::Denied),
        Verdict::Failed => error(AgentError::Prompt),
        _ => Reply::Done,
    }
}

/// The Touch ID reason: who signs what with which key, and for a login to which host. None (the pinentry, which says
/// why) for a forwarded request, a failed session-bind, or a login to a host that is not verified.
fn touch_reason(profile: &str, caller: &Caller, key: &Key, s: &SignContext, forwarded: bool) -> Option<String> {
    let with = format!("with the SSH key \"{}\"", super::cut(&key.name, 12));
    // At most 75 characters: the user, the start of the host key's fingerprint (the pinentry has it whole), the key.
    let what = match (&s.data, &s.bound) {
        (Data::Login { user, bound: true }, Some(b)) => {
            format!("log in as \"{}\" to {} {with}", super::cut(user, 12), super::cut(&host_key(b), 15))
        }
        (Data::Login { .. }, _) => return None,
        (Data::Other, _) => format!("sign data that is not an SSH login {with}"),
    };
    if forwarded || s.bind_refused {
        return None;
    }
    super::touch_reason(profile, caller, &what)
}

/// The question: the profile, the client, what is signed (a login, and where to, or data that is not a login), the
/// key, whether the request is forwarded or its session-bind failed, and how long a yes lasts.
fn text(ctx: &Ctx, caller: &Caller, key: &Key, s: &SignContext, always: bool) -> String {
    let (what, dest) = match (&s.data, &s.bound) {
        (Data::Login { user, bound: true }, Some(b)) => {
            (format!("log in as {}", quoted(user)), format!(" to the host whose key is {}", host_key(b)))
        }
        (Data::Login { user, .. }, _) => (
            format!("log in as {}", quoted(user)),
            " to a host that is not verified (no session-bind for this login)".to_owned(),
        ),
        (Data::Other, bound) => (
            "sign data that is NOT an SSH login (a git commit, a file, a challenge)".to_owned(),
            bound
                .as_ref()
                .map(|b| format!(" on a connection to the host whose key is {}", host_key(b)))
                .unwrap_or_default(),
        ),
    };
    let forwarded = if s.bound.as_ref().is_some_and(|b| b.forwarded) {
        " The request is FORWARDED from a remote host (ssh -A)."
    } else {
        ""
    };
    let refused = if s.bind_refused {
        " A session-bind on this connection failed: where it says it goes is not proven."
    } else {
        ""
    };
    let scope = if always {
        " [always: this process and this key, until the profile locks]"
    } else {
        " (asked every time for this client)"
    };
    format!(
        "dybw profile {}: allow {} to {what}{dest} with the SSH key {} ({})?{forwarded}{refused}{scope}",
        ctx.profile.name,
        client(caller, &s.client),
        quoted(&key.name),
        key.fingerprint
    )
}

/// Unlock the profile for an SSH signature asked by `caller`: `Done` at once when it is unlocked; a refusal without a
/// question when this client cancelled such an unlock before (until the profile unlocks); otherwise the master
/// password question, which names the client. A cancel is remembered for this client.
pub(super) async fn unlock<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, caller: &Caller, why: &str) -> Reply {
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    if shared.state.borrow().ssh_declined.contains(caller) {
        tracing::info!(profile = %ctx.profile.name, "not asking again to unlock for an SSH client that cancelled");
        return error(AgentError::Denied);
    }
    let reply = unlock_profile(shared, host, ctx, caller, Some(why), true).await;
    if reply == error(AgentError::Denied) {
        let declined = &mut shared.state.borrow_mut().ssh_declined;
        if declined.len() >= MAX_HELD {
            declined.remove(0);
        }
        declined.push(caller.clone());
    }
    reply
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    use ssh_key::{HashAlg, PrivateKey};

    use super::*;
    use crate::caller::Programs;
    use crate::ssh_agent::Binding;

    #[test]
    fn touch_id_names_a_verified_login_or_data_and_leaves_every_warning_to_the_pinentry() {
        let host = PrivateKey::new(KeypairData::from(Ed25519Keypair::from_seed(&[7; 32])), "").unwrap();
        let fp = host.public_key().fingerprint(HashAlg::Sha256).to_string();
        let key = Key { id: "k1".into(), name: "work key".into(), fingerprint: "SHA256:x".into(), blob: vec![] };
        let who = Caller::Invoker {
            exe: format!("/opt/{}", "s".repeat(48)).into(),
            script: None,
            hash: "h".into(),
            relative: false,
            at: crate::caller::At::default(),
        };
        let bound = |forwarded| Some(Binding { host_key: host.public_key().clone(), forwarded });
        let login = |bound| Data::Login { user: "git".into(), bound };
        let ctx = |data, bound, bind_refused| SignContext {
            profile: "work".into(),
            data,
            bound,
            bind_refused,
            client: Programs::default(),
        };
        let reason = |s: &SignContext, forwarded| touch_reason("work", &who, &key, s, forwarded);
        let prefix: String = fp.chars().take(14).collect();
        assert_eq!(
            reason(&ctx(login(true), bound(false), false), false).unwrap(),
            format!(
                "log in as \"git\" to {prefix}… with the SSH key \"work key\" (dybw profile work) for sssssssssssssssssss…"
            )
        );
        // A long user is cut; the host key's start and the profile always fit.
        let long = Data::Login { user: "u".repeat(80), bound: true };
        let cut = touch_reason("p".repeat(64).as_str(), &who, &key, &ctx(long, bound(false), false), false).unwrap();
        assert!(cut.chars().count() <= 120, "{cut}");
        assert!(cut.starts_with(&format!("log in as \"{}…\" to {prefix}…", "u".repeat(11))), "{cut}");
        assert!(cut.contains(&format!("(dybw profile {}…) for {}", "p".repeat(11), "s".repeat(12))), "{cut}");
        let data = reason(&ctx(Data::Other, None, false), false).unwrap();
        assert!(data.contains("sign data that is not an SSH login with the SSH key \"work key\""), "{data}");
        assert_eq!(reason(&ctx(login(false), bound(false), false), false), None, "a host that is not verified");
        assert_eq!(reason(&ctx(login(true), None, false), false), None, "no binding: no host to name");
        assert_eq!(reason(&ctx(login(true), bound(true), false), true), None, "forwarded");
        assert_eq!(reason(&ctx(Data::Other, None, true), false), None, "a failed session-bind");
        // Callers without a stable identity: the pinentry only, which names them and the host in full (ruling).
        let ai = Caller::Ai { harness: "claude".into(), via: crate::caller::Via::Ancestry };
        let unknown = Caller::Unknown { why: "orphan".into(), peer: None };
        for caller in [ai, unknown, crate::agent::testing::invoker()] {
            assert_eq!(touch_reason("work", &caller, &key, &ctx(login(true), bound(false), false), false), None);
        }
    }
}
