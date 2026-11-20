//! The SSH agent's decisions on the profile's worker (P4.5, profiles §8, ADR 0012): the confirmation of a signature
//! and the unlock a signature asks for. On the worker, so a lock cancels a question in flight and drops every
//! "always" given for the profile's keys.

use dybw_proto::{AgentError, Reply};

use super::{MAX_HELD, Shared, error, quoted, unlock as unlock_profile};
use crate::caller::Caller;
use crate::host::Host;
use crate::policy::{self, Access, Decision, Store, Verdict};
use crate::session::{self, Ctx};
use crate::ssh::Key;
use crate::ssh_agent::{Data, SignContext, client, host_key, sign_event};

/// May "always" be offered to this SSH client? Only to a named one whose parent is still there: never to an AI-class
/// or unknown client (confirmed every time, ADR 0012), nor to a detached one.
fn rememberable(caller: &Caller) -> bool {
    matches!(caller, Caller::Invoker { .. }) && !caller.detached()
}

/// Ask whether `caller` may sign with `key`, unless this very process (pid, start time and image) holds an "always"
/// for this key. One question on the screen at a time; a held answer is looked for again once this request has the
/// screen. Every decision is audited. `Done` allows the signature.
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
    let always = rememberable(caller);
    let grant = (caller.clone(), key.blob.clone());
    let held = || always && shared.state.borrow().ssh_held.contains(&grant);
    let verdict = if held() {
        Verdict::Granted
    } else {
        let _screen = shared.asking.lock().await;
        if held() {
            Verdict::Granted
        } else {
            match session::confirm(host, &text(ctx, caller, key, sign, always), always).await {
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
                Err(_) => Verdict::Declined,
            }
        }
    };
    ctx.audit.record(sign_event(caller, key, sign, verdict));
    match verdict {
        Verdict::Declined => error(AgentError::Denied),
        Verdict::Failed => error(AgentError::Prompt),
        _ => Reply::Done,
    }
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
    let reply = unlock_profile(shared, host, ctx, Some(why)).await;
    if reply == error(AgentError::Denied) {
        let declined = &mut shared.state.borrow_mut().ssh_declined;
        if declined.len() >= MAX_HELD {
            declined.remove(0);
        }
        declined.push(caller.clone());
    }
    reply
}
