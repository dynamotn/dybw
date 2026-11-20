//! The consumer of `pam_bwss` (ADR 0006, Linux): the agent takes what the PAM module put in the user's kernel keyring
//! and passes it on. Ruled for P4.6: polled at start and every [`POLL`] while any profile has a `login` protector (a
//! keyring search is cheap; no notification is relied on).
//!
//! - `dybw:login` (a login, a screen unlock): every profile with the protector unlocks with it.
//! - `dybw:login-old` with `dybw:login` (a password change): every such profile wraps its key again for the new one.
//!   The old entry is written first, so it is there whenever the new one is.
//! - `dybw:lock` (a session closed): when the session it names was the user's last open logind session, every
//!   profile locks; `-` (no session id) is ignored. The agent has no D-Bus client: logind's state is read from its
//!   session files under `/run/systemd/sessions`.
//!
//! Each entry is read once and invalidated at once; the password is wiped when the last worker is done with it.

use std::path::Path;
use std::time::SystemTime;

use dybw_proto::Reply;
use tokio::sync::oneshot::Receiver;
use zeroize::Zeroizing;

use crate::agent::Agent;
use crate::paths::ProfilePaths;
use crate::policy::{AuditEvent, Verdict};
use crate::worker::{Cmd, LOGIN as PROTECTOR, Token, the_agent};

/// The login password, at a login or a screen unlock; the new one at a password change.
pub const LOGIN: &str = "dybw:login";
/// The old password at a password change.
pub const LOGIN_OLD: &str = "dybw:login-old";
/// A session closed; its payload is the session id, or `-`.
pub const LOCK: &str = "dybw:lock";

/// How often the keyring is looked at.
#[cfg(target_os = "linux")]
pub const POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// The user's kernel keyring: a port, so the tests fake it.
pub trait Keyring: Send + Sync {
    /// Take the entry `name`: its payload, the entry gone. `None` when there is none or it cannot be read.
    fn take(&self, name: &str) -> Option<Zeroizing<Vec<u8>>>;
}

/// The real keyring, `@u`. A failure is logged once: `dybw doctor` says why.
#[cfg(target_os = "linux")]
pub struct UserKeyring;

#[cfg(target_os = "linux")]
impl Keyring for UserKeyring {
    fn take(&self, name: &str) -> Option<Zeroizing<Vec<u8>>> {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        dybw_peer::keyring::take(name).unwrap_or_else(|e| {
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!("the user keyring cannot be read ({e}): no login password is handed over");
            }
            None
        })
    }
}

/// Look at the keyring every [`POLL`], from now until the agent stops.
#[cfg(target_os = "linux")]
pub async fn watch(agent: std::sync::Arc<Agent>, keyring: std::sync::Arc<dyn Keyring>) {
    let mut tick = tokio::time::interval(POLL);
    loop {
        tick.tick().await;
        drop(agent.handover(&*keyring, Path::new("/run/systemd/sessions")).await);
    }
}

/// Whether `uid` has a user session open in logind besides `closing`: a session file under `dir` with its `UID`, a
/// `CLASS` of `user*` and a `STATE` other than `closing`. No readable directory: none.
pub(crate) fn others_open(dir: &Path, uid: u32, closing: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else { return false };
    let uid = uid.to_string();
    entries.flatten().any(|e| {
        // The `<id>.ref` entries are FIFOs: never read one.
        let file = e.file_type().is_ok_and(|t| t.is_file()) && e.file_name().to_str() != Some(closing);
        let text = if file { std::fs::read_to_string(e.path()).unwrap_or_default() } else { String::new() };
        let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('='));
        field("UID") == Some(&uid)
            && field("CLASS").is_some_and(|c| c.starts_with("user"))
            && field("STATE").is_some_and(|s| s != "closing")
    })
}

impl Agent {
    /// The profiles with a `login` protector on this device.
    fn with_login(&self) -> Vec<String> {
        let enrolled = |p: &crate::config::Profile| ProfilePaths::with(&self.home, p).unlock.join(PROTECTOR).exists();
        self.config.names().into_iter().filter(|n| self.config.profile(Some(n)).is_ok_and(|p| enrolled(&p))).collect()
    }

    /// One look at the keyring (see the module's text); `sessions` is logind's session directory. Every entry is taken
    /// first; a lock is done before this returns; a password is queued on each profile's worker, in order with the
    /// rest of its work, and not waited for (a worker busy with a pinentry must not stall the next look). The answers
    /// come on the receivers returned, which the watch drops.
    pub(crate) async fn handover(&self, keyring: &dyn Keyring, sessions: &Path) -> Vec<Receiver<Reply>> {
        let names = self.with_login();
        if names.is_empty() {
            return Vec::new();
        }
        let lock = keyring.take(LOCK);
        let token = keyring.take(LOGIN);
        // The old password comes only with a new one; one equal to it (a leftover) is no change.
        let old = token.as_ref().and_then(|_| keyring.take(LOGIN_OLD)).filter(|old| Some(old) != token.as_ref());
        if let Some(lock) = lock {
            self.lock_session(&lock, sessions).await;
        }
        let Some(token) = token else { return Vec::new() };
        tracing::info!(change = old.is_some(), "a login password was handed over");
        let mut answers = Vec::new();
        for name in &names {
            let worker = self.config.profile(Some(name)).ok().and_then(|p| self.worker(&p));
            let cmd = || Cmd::LoginToken { token: Token(token.clone()), old: old.clone().map(Token) };
            answers.extend(worker.map(|w| w.post(cmd(), self.clock.mono())));
        }
        answers
    }

    /// A session closed: lock every profile when it was the user's last, each audited.
    async fn lock_session(&self, id: &[u8], sessions: &Path) {
        let id = String::from_utf8_lossy(id);
        // `-`: pam_systemd did not run before pam_bwss, so the session is unknown.
        if id == "-" || others_open(sessions, self.uid, &id) {
            return;
        }
        tracing::info!("the last session closed: locking every profile");
        for name in self.config.names() {
            let Some(worker) = self.running(&name) else { continue };
            worker.call(Cmd::Lock, self.clock.mono()).await;
            self.audit.record(AuditEvent {
                time: SystemTime::now(),
                profile: name,
                caller: the_agent(),
                op: "lock-session",
                kind: Some(PROTECTOR),
                item: None,
                verdict: Verdict::Confirmed,
                ssh: None,
            });
        }
    }
}

#[cfg(test)]
#[path = "handover_tests.rs"]
mod tests;
