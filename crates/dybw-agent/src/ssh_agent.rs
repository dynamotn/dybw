//! The OpenSSH agent protocol on `ssh-agent.sock` (P4.5, profiles §8), written from draft-miller-ssh-agent and
//! OpenSSH's `PROTOCOL.agent` and `ssh-agent.c`. It offers the SSH keys of the unlocked profiles in
//! `[ssh_agent] profiles`, signs with them once [`Authorize`] allows it, and never returns or takes a private key.
//!
//! A connection is persistent and served one message at a time: `uint32` length, then the message, at most
//! [`MAX_MESSAGE`] bytes. A frame that is oversized, empty or cut short, or a known message whose fields are cut
//! short, closes that connection; the agent keeps serving the others. An unknown message type is answered with
//! `SSH_AGENT_FAILURE`, as OpenSSH does.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dybw_native::prompter::one_line;
use dybw_proto::{Reply, SshKey, SshProfile};
use signature::Verifier;
use ssh_key::encoding::Decode;
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::agent::Agent;
use crate::caller::{At, Caller, Resolved};
use crate::policy::{AuditEvent, SignAudit, Verdict, shown};
use crate::ssh::{Key, RSA_SHA2_256, RSA_SHA2_512};
use crate::worker::Cmd;

/// OpenSSH's `AGENT_MAX_LEN`: the largest message either side accepts.
pub const MAX_MESSAGE: usize = 256 * 1024;
/// How long a connection may wait between two messages. OpenSSH's agent has no limit, but its clients hold a
/// connection only for one login (`ssh` closes it after authentication) or one command (`ssh-add`, `git`); ten
/// minutes covers a login waiting on other prompts and still reaps connections a client leaked. Once a message has
/// begun, the rest of it is due within the agent's read timeout.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Most SSH connections served at once. Idle ones may stay open for [`IDLE_TIMEOUT`]: past the cap a new one is
/// closed at once, so they cannot take every descriptor of the agent.
pub const MAX_CONNECTIONS: usize = 64;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const EXTENSION: u8 = 27;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// OpenSSH's `AGENT_MAX_SID_LEN` and `AGENT_MAX_SESSION_IDS`.
const MAX_SESSION_ID: usize = 128;
const MAX_BINDS: usize = 16;
/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252).
const USERAUTH_REQUEST: u8 = 50;

/// What the data to sign is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// Not an SSH login with this key: `ssh-keygen -Y sign` (a git commit), or anything else.
    Other,
    /// A `publickey` userauth request (RFC 4252 §7) with this key, to log in as `user`. `bound`: its session is the
    /// one this connection bound last (and, for `publickey-hostbound-v00@openssh.com`, so is its host key), so
    /// [`SignContext::bound`] is the host it logs in to.
    Login { user: String, bound: bool },
}

/// The destination a connection was bound to with `session-bind@openssh.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The host key the connection bound last.
    pub host_key: PublicKey,
    /// Some hop was forwarded (`ssh -A`): the request comes from a remote host.
    pub forwarded: bool,
}

/// What a sign request asks, for the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignContext {
    /// The profile whose key it is.
    pub profile: String,
    pub data: Data,
    pub bound: Option<Binding>,
    /// A `session-bind@openssh.com` on this connection was refused (bad signature, a second bind of a login
    /// connection, ...): what the client says of its destination is not to be trusted.
    pub bind_refused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Refuse,
}

/// The decision on each signature: confirmation, policy and audit (P4.5 Task 3). It may wait on the user; the
/// peer is re-checked after it answers, before anything is signed.
pub trait Authorize: Send + Sync {
    fn authorize_sign<'a>(
        &'a self,
        who: &'a Resolved,
        key: &'a Key,
        ctx: &'a SignContext,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>>;
}

/// Refuses every signature.
pub struct RefuseAll;

impl Authorize for RefuseAll {
    fn authorize_sign<'a>(
        &'a self,
        _: &'a Resolved,
        _: &'a Key,
        _: &'a SignContext,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        tracing::warn!("SSH signatures are refused");
        Box::pin(std::future::ready(Decision::Refuse))
    }
}

/// The agent's decision (profiles §8, ADR 0012): the key's profile worker asks the user through its trusted
/// pinentry, unless this client process holds an "always" for this key, and audits the answer. AI-class and
/// unknown clients are asked every time. A profile that locked meanwhile refuses.
pub struct Confirm(pub Arc<Agent>);

impl Authorize for Confirm {
    fn authorize_sign<'a>(
        &'a self,
        who: &'a Resolved,
        key: &'a Key,
        ctx: &'a SignContext,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move {
            let Some(worker) = self.0.running(&ctx.profile) else { return Decision::Refuse };
            let cmd = Cmd::SshConfirm { caller: who.caller.clone(), key: key.clone(), ctx: ctx.clone() };
            if worker.call(cmd, self.0.clock.mono()).await == Reply::Done { Decision::Allow } else { Decision::Refuse }
        })
    }
}

/// The SSH client a question or a log line names, with its class: the program and the one that ran it, an AI
/// agent's client, or one that cannot be named.
pub(crate) fn client(caller: &Caller) -> String {
    let path = |p: &std::path::Path| shown(&p.to_string_lossy(), 120);
    match caller {
        Caller::Invoker { exe, at: At { parent, detached, .. }, .. } => {
            let parent = parent.as_deref().map(|p| format!(" (run by {})", path(p))).unwrap_or_default();
            let detached = if *detached { format!(", {}", crate::policy::DETACHED) } else { String::new() };
            format!("the SSH client {}{parent}{detached}", path(exe))
        }
        Caller::Ai { harness, .. } => format!("an SSH client of the AI agent {}", one_line(harness)),
        Caller::Unknown { why, peer } => {
            let exe = peer.as_deref().map(|p| format!(" {}", path(p))).unwrap_or_default();
            format!("an SSH client{exe} that cannot be identified ({}), possibly an AI agent", one_line(why))
        }
    }
}

/// The `SHA256:` fingerprint of the host key a connection is bound to.
pub(crate) fn host_key(bound: &Binding) -> String {
    bound.host_key.fingerprint(HashAlg::Sha256).to_string()
}

/// The audit line of one decision on a signature: never the data signed.
pub(crate) fn sign_event(caller: &Caller, key: &Key, ctx: &SignContext, verdict: Verdict) -> AuditEvent {
    AuditEvent {
        time: std::time::SystemTime::now(),
        profile: ctx.profile.clone(),
        caller: caller.clone(),
        op: "ssh-sign",
        kind: Some(if matches!(ctx.data, Data::Login { .. }) { "login" } else { "data" }),
        item: Some(key.id.clone()),
        verdict,
        ssh: Some(SignAudit {
            key: key.fingerprint.clone(),
            dest: ctx.bound.as_ref().map(host_key),
            forwarded: ctx.bound.as_ref().is_some_and(|b| b.forwarded),
        }),
    }
}

/// The SSH agent's state, shared by its connections.
pub struct SshAgent {
    agent: Arc<Agent>,
    /// `[ssh_agent] profiles`, in order.
    profiles: Vec<String>,
    authorize: Arc<dyn Authorize>,
    /// The keys `ssh-add -d` and `-D` took out of this agent's view, by public key, until the agent ends. The vault
    /// is never touched.
    removed: Mutex<HashSet<Vec<u8>>>,
    pub(crate) idle_timeout: Duration,
    /// One permit per connection served, [`MAX_CONNECTIONS`] in all.
    pub(crate) slots: Arc<tokio::sync::Semaphore>,
    /// Key listings answered since the agent started (`dybw doctor`): listings are not audited one by one.
    lists: AtomicU64,
    /// One unlock question for a signature at a time.
    unlocking: tokio::sync::Mutex<()>,
}

impl SshAgent {
    pub fn new(agent: Arc<Agent>, profiles: Vec<String>, authorize: Arc<dyn Authorize>) -> SshAgent {
        SshAgent {
            agent,
            profiles,
            authorize,
            removed: Mutex::default(),
            idle_timeout: IDLE_TIMEOUT,
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            lists: AtomicU64::new(0),
            unlocking: tokio::sync::Mutex::new(()),
        }
    }

    /// Each profile of `[ssh_agent] profiles` in order, with its keys, or `None` while it is locked.
    async fn by_profile(&self) -> Vec<(String, Option<Vec<Key>>)> {
        self.agent.guard().await;
        let mut out = Vec::new();
        for name in &self.profiles {
            let keys = match self.agent.running(name) {
                Some(worker) => {
                    let (tx, listed) = oneshot::channel();
                    worker.call(Cmd::SshKeys(tx), self.agent.clock.mono()).await;
                    listed.await.ok()
                }
                None => None,
            };
            out.push((name.clone(), keys));
        }
        out
    }

    /// The keys offered of `by_profile`, each once, with its profile: those of the unlocked profiles, less the removed
    /// ones.
    fn offered(&self, by_profile: &[(String, Option<Vec<Key>>)]) -> Vec<(String, Key)> {
        let mut keys: Vec<(String, Key)> = Vec::new();
        for (name, listed) in by_profile {
            for key in listed.iter().flatten() {
                if !keys.iter().any(|(_, k)| k.blob == key.blob) {
                    keys.push((name.clone(), key.clone()));
                }
            }
        }
        let removed = self.removed.lock().unwrap_or_else(PoisonError::into_inner);
        keys.retain(|(_, k)| !removed.contains(&k.blob));
        keys
    }

    /// The keys offered now ([`SshAgent::offered`]). Read afresh for every message and never kept by a connection,
    /// so a key whose profile has locked is gone from the next answer.
    async fn keys(&self) -> Vec<(String, Key)> {
        self.offered(&self.by_profile().await)
    }

    /// The offered key `blob`, with its profile.
    async fn find(&self, blob: &[u8]) -> Option<(String, Key)> {
        self.keys().await.into_iter().find(|(_, k)| k.blob == blob)
    }

    /// `dybw ssh list` and `dybw doctor`: the keys offered now, which profiles are unlocked, and how many listings
    /// SSH clients asked for. Names and fingerprints only.
    pub(crate) async fn listing(&self) -> Reply {
        let by_profile = self.by_profile().await;
        let kind = |blob: &[u8]| String::from_utf8_lossy(Reader(blob).string().unwrap_or_default()).into_owned();
        let keys = self.offered(&by_profile).into_iter();
        let keys =
            keys.map(|(profile, k)| SshKey { kind: kind(&k.blob), name: k.name, fingerprint: k.fingerprint, profile });
        let profiles = by_profile.into_iter().map(|(name, keys)| SshProfile { name, unlocked: keys.is_some() });
        Reply::SshKeys { keys: keys.collect(), profiles: profiles.collect(), lists: self.lists.load(Ordering::Relaxed) }
    }

    /// The key `blob` once the locked profiles are unlocked one by one, in config order, until one holds it: while a
    /// profile is locked nothing of its keys is known (ADR 0025 keeps no index). One unlock question at a time; an
    /// unlocked profile asks nothing, and one whose unlock this client cancelled asks it nothing more until it
    /// unlocks.
    async fn unlock_for(&self, who: &Resolved, blob: &[u8]) -> Option<(String, Key)> {
        // The main socket's rule: no master-password question on behalf of an AI-class client.
        if !crate::agent::may_unlock(&who.caller) {
            let locked = self.by_profile().await.into_iter().find(|(_, keys)| keys.is_none());
            if let Some((profile, _)) = locked {
                tracing::warn!(%profile, "refused to unlock for an AI-class SSH client");
                let fingerprint = PublicKey::from_bytes(blob).map(|k| k.fingerprint(HashAlg::Sha256).to_string());
                self.agent.audit.record(AuditEvent {
                    time: std::time::SystemTime::now(),
                    profile,
                    caller: who.caller.clone(),
                    op: "ssh-sign",
                    kind: None,
                    item: None,
                    verdict: Verdict::Denied,
                    ssh: Some(SignAudit { key: fingerprint.unwrap_or_default(), dest: None, forwarded: false }),
                });
            }
            return None;
        }
        let _one = self.unlocking.lock().await;
        let why = format!("an SSH signature asked by {}", client(&who.caller));
        for name in &self.profiles {
            if let Some(found) = self.find(blob).await {
                return Some(found);
            }
            self.agent.ssh_unlock(name, who.caller.clone(), why.clone()).await;
        }
        self.find(blob).await
    }

    /// Take `blob`, or every key offered now (`None`), out of the view; false when `blob` is not offered.
    async fn remove(&self, blob: Option<&[u8]>) -> bool {
        let keys = self.keys().await;
        let mut removed = self.removed.lock().unwrap_or_else(PoisonError::into_inner);
        match blob {
            None => {
                removed.extend(keys.into_iter().map(|(_, k)| k.blob));
                true
            }
            Some(blob) => keys.iter().any(|(_, k)| k.blob == blob) && removed.insert(blob.to_vec()),
        }
    }

    /// A signature with `blob` over `data`: found among the offered keys (or once a locked profile is unlocked for
    /// it), checked, decided by [`Authorize`], and made by the key's worker. A refusal without asking, and anything
    /// that stops the signature after a yes, is audited here; the decision itself by [`Authorize`].
    async fn sign(&self, who: &Resolved, conn: &Conn, blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
        let found = match self.find(blob).await {
            Some(found) => Some(found),
            None => self.unlock_for(who, blob).await,
        };
        let Some((profile, key)) = found else {
            tracing::info!("refused to sign with a key that is not offered");
            return None;
        };
        let ctx = conn.context(profile, data, blob);
        let refuse = |verdict: Verdict, why: &str| {
            tracing::warn!(profile = %ctx.profile, "refused an SSH signature: {why}");
            self.agent.audit.record(sign_event(&who.caller, &key, &ctx, verdict));
            None
        };
        // As OpenSSH's process_sign_request: a connection whose session-bind failed, and that has no bind, signs
        // nothing.
        if conn.bind_refused && conn.binds.is_empty() {
            return refuse(Verdict::Denied, "the connection's session-bind failed");
        }
        // Certain to fail in `ssh::sign`: refused before anyone is asked.
        if Reader(blob).string() == Some(b"ssh-rsa") && flags & (RSA_SHA2_256 | RSA_SHA2_512) == 0 {
            return refuse(Verdict::Denied, "RSA with SHA-1 (no rsa-sha2 flag)");
        }
        if self.authorize.authorize_sign(who, &key, &ctx).await != Decision::Allow {
            return None;
        }
        if !self.agent.resolver.recheck(who) {
            return refuse(Verdict::Denied, "the SSH client changed while it was being served");
        }
        // `ssh-add -d` may have taken the key out of the view while the user was being asked.
        if self.removed.lock().unwrap_or_else(PoisonError::into_inner).contains(blob) {
            return refuse(Verdict::Denied, "the key was removed while the user was asked");
        }
        let Some(worker) = self.agent.running(&ctx.profile) else {
            return refuse(Verdict::Failed, "the profile locked");
        };
        let (out, signed) = oneshot::channel();
        let cmd = Cmd::SshSign { id: key.id.clone(), blob: blob.to_vec(), data: data.to_vec(), flags, out };
        worker.call(cmd, self.agent.clock.mono()).await;
        // Nothing comes back when the profile locked meanwhile.
        match signed.await {
            Ok(Ok(signature)) => Some(signature),
            Ok(Err(e)) => refuse(Verdict::Failed, &e.to_string()),
            Err(_) => refuse(Verdict::Failed, "the profile locked"),
        }
    }

    /// The reply to one message, or `None` when its fields are cut short.
    async fn answer(&self, who: &Resolved, conn: &mut Conn, message: &[u8]) -> Option<Vec<u8>> {
        let mut msg = Reader(message);
        let status = |ok: bool| vec![if ok { SUCCESS } else { FAILURE }];
        Some(match msg.u8()? {
            REQUEST_IDENTITIES => {
                self.lists.fetch_add(1, Ordering::Relaxed);
                let keys = self.keys().await;
                let mut out = vec![IDENTITIES_ANSWER];
                out.extend_from_slice(&u32::try_from(keys.len()).unwrap_or(u32::MAX).to_be_bytes());
                for (_, key) in &keys {
                    put_string(&mut out, &key.blob);
                    put_string(&mut out, key.name.as_bytes());
                }
                out
            }
            SIGN_REQUEST => {
                let (blob, data, flags) = (msg.string()?, msg.string()?, msg.u32()?);
                match self.sign(who, conn, blob, data, flags).await {
                    Some(signature) => {
                        let mut out = vec![SIGN_RESPONSE];
                        put_string(&mut out, &signature);
                        out
                    }
                    None => status(false),
                }
            }
            REMOVE_IDENTITY => status(self.remove(Some(msg.string()?)).await),
            REMOVE_ALL_IDENTITIES => status(self.remove(None).await),
            // OpenSSH answers an unknown extension with a plain failure, as the draft asks, not EXTENSION_FAILURE.
            EXTENSION => status(msg.string()? == SESSION_BIND && conn.bind(&mut msg)?),
            // Adding keys (17, 25), smartcards (20, 21, 26), lock and unlock (22, 23), and anything unknown.
            _ => status(false),
        })
    }
}

/// Serve one connection until the client closes it, idles past the idle timeout, or sends a bad message.
pub async fn handle(ssh: Arc<SshAgent>, mut stream: UnixStream) {
    let Ok(_slot) = ssh.slots.clone().try_acquire_owned() else {
        tracing::warn!("too many SSH agent connections: closed a new one");
        return;
    };
    let Some(who) = crate::server::identify(&ssh.agent, &stream, true).await else { return };
    let limit = ssh.agent.read_timeout;
    let mut conn = Conn::default();
    while let Some(message) = read_message(&mut stream, ssh.idle_timeout, limit).await {
        let Some(reply) = ssh.answer(&who, &mut conn, &message).await else {
            tracing::warn!("refused a malformed SSH agent message, closing the connection");
            return;
        };
        let mut frame = Vec::with_capacity(4 + reply.len());
        put_string(&mut frame, &reply);
        if !matches!(tokio::time::timeout(limit, stream.write_all(&frame)).await, Ok(Ok(()))) {
            return;
        }
    }
}

/// The next message, or `None` on EOF, a read error, a timeout, or a length that is zero or over [`MAX_MESSAGE`].
/// The buffer is wiped on drop: an `ssh-add` of a key file sends the private key before it is refused.
async fn read_message(stream: &mut UnixStream, idle: Duration, limit: Duration) -> Option<Zeroizing<Vec<u8>>> {
    let mut len = [0; 4];
    tokio::time::timeout(idle, stream.read_exact(&mut len[..1])).await.ok()?.ok()?;
    let rest = async {
        stream.read_exact(&mut len[1..]).await.ok()?;
        let len = usize::try_from(u32::from_be_bytes(len)).ok().filter(|n| (1..=MAX_MESSAGE).contains(n));
        let Some(len) = len else {
            tracing::warn!("refused an SSH agent message of a bad length, closing the connection");
            return None;
        };
        let mut message = Zeroizing::new(vec![0; len]);
        stream.read_exact(&mut message).await.ok()?;
        Some(message)
    };
    tokio::time::timeout(limit, rest).await.ok()?
}

/// The SSH wire format's `string`: a `uint32` length, then the bytes.
fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(s);
}

/// Reads the SSH wire format; `None` when the input is cut short.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok()?;
        self.take(n)
    }
}

/// One connection's `session-bind@openssh.com` record.
#[derive(Default)]
struct Conn {
    binds: Vec<Bind>,
    bind_refused: bool,
}

struct Bind {
    host_key: PublicKey,
    session_id: Vec<u8>,
    forwarded: bool,
}

impl Conn {
    /// `session-bind@openssh.com` (string host key, string session id, string signature, bool is_forwarding):
    /// `None` when it is cut short, else whether it was recorded.
    fn bind(&mut self, msg: &mut Reader<'_>) -> Option<bool> {
        let (host_key, session_id, signature, forwarded) = (msg.string()?, msg.string()?, msg.string()?, msg.u8()?);
        let recorded = self.record(host_key, session_id, signature, forwarded != 0);
        self.bind_refused |= !recorded;
        Some(recorded)
    }

    /// The rules of OpenSSH's `process_ext_session_bind` (ssh-agent.c, OpenSSH 8.9 and later): the host key's
    /// signature over the session id must verify; a connection already bound for its own login (not forwarded)
    /// takes no further bind; the same session id again is accepted with the same host key and refused with
    /// another; at most 16 binds.
    fn record(&mut self, host_key: &[u8], session_id: &[u8], signature: &[u8], forwarded: bool) -> bool {
        let Ok(host_key) = PublicKey::from_bytes(host_key) else { return false };
        let mut signature = signature;
        let Ok(sig) = Signature::decode(&mut signature) else { return false };
        if session_id.len() > MAX_SESSION_ID
            || !signature.is_empty()
            || Verifier::verify(&host_key, session_id, &sig).is_err()
        {
            return false;
        }
        for bind in &self.binds {
            if !bind.forwarded {
                return false;
            }
            if bind.session_id == session_id {
                return bind.host_key.key_data() == host_key.key_data();
            }
        }
        if self.binds.len() >= MAX_BINDS {
            return false;
        }
        self.binds.push(Bind { host_key, session_id: session_id.to_vec(), forwarded });
        true
    }

    /// The context of signing `data` with `key` (a wire-format public key) of `profile` on this connection.
    fn context(&self, profile: String, data: &[u8], key: &[u8]) -> SignContext {
        let last = self.binds.last();
        let data = match userauth(data, key) {
            None => Data::Other,
            Some(Login { user, session_id, host_key }) => {
                let bound = last.is_some_and(|b| {
                    b.session_id == session_id
                        && host_key.is_none_or(|h| {
                            PublicKey::from_bytes(h).is_ok_and(|h| h.key_data() == b.host_key.key_data())
                        })
                });
                Data::Login { user, bound }
            }
        };
        let forwarded = self.binds.iter().any(|b| b.forwarded);
        let bound = last.map(|b| Binding { host_key: b.host_key.clone(), forwarded });
        SignContext { profile, data, bound, bind_refused: self.bind_refused }
    }
}

/// What a userauth request says.
#[derive(Debug, PartialEq, Eq)]
struct Login<'a> {
    user: String,
    session_id: &'a [u8],
    /// The server's host key, in a `publickey-hostbound-v00@openssh.com` request.
    host_key: Option<&'a [u8]>,
}

/// The userauth request `data` is, signed with `key`; `None` for any other data. As OpenSSH's
/// `parse_userauth_request`: a non-empty session id, then `SSH_MSG_USERAUTH_REQUEST`, the user, `ssh-connection`,
/// the method, TRUE, a known algorithm, this key, the host key for the hostbound method, and nothing after.
fn userauth<'a>(data: &'a [u8], key: &[u8]) -> Option<Login<'a>> {
    let mut r = Reader(data);
    let session_id = r.string().filter(|s| !s.is_empty())?;
    let head_ok = r.u8()? == USERAUTH_REQUEST;
    let user = String::from_utf8(r.string()?.to_vec()).ok()?;
    let service_ok = r.string()? == b"ssh-connection";
    let method = r.string()?;
    let follows = r.u8()? == 1;
    let algorithm = std::str::from_utf8(r.string()?).ok().and_then(|a| Algorithm::new(a).ok());
    let key_ok = r.string()? == key;
    let host_key = match method {
        b"publickey" => None,
        b"publickey-hostbound-v00@openssh.com" => Some(r.string()?),
        _ => return None,
    };
    let ok = head_ok && service_ok && follows && algorithm.is_some() && key_ok && r.0.is_empty();
    ok.then_some(Login { user, session_id, host_key })
}

#[cfg(test)]
mod tests;
